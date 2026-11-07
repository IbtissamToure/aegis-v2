"""Prompt-injection detector (direct and indirect), English and Arabic.

Design:
  * text is normalized (NFKC, zero-width removed, Arabic unified) and also
    "de-obfuscated" (spaced-out letters joined, leetspeak mapped, base64 blobs
    decoded) so trivial obfuscation does not hide a signature;
  * signatures are grouped into attack *families*; each family contributes its
    strongest signal, and families combine with a noisy-OR:
        score = 1 - prod_f (1 - w_f)
  * instructions found inside supplied CONTENT (documents, emails, tool output)
    are treated as indirect injection and weighted higher, because data should
    not address the model.

This is a heuristic detector. It does not and cannot guarantee complete
protection against prompt injection; the evaluation reports its misses.
"""
from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from aegis.models import InjectionResult, InjectionSignal, Severity
from aegis.text import normalize

F = re.IGNORECASE | re.MULTILINE

_TARGETS = r"(?:instructions?|rules?|guidelines?|directions?|prompts?|commands?|constraints?|restrictions?|polic(?:y|ies)|programming|guardrails?|directives?|context)"
SIGNATURES: dict[str, list[tuple[re.Pattern, float, str]]] = {
    "instruction_override": [
        (re.compile(rf"\b(?:ignore|disregard|forget|override|overwrite|skip|abandon|discard)\s+(?:(?:all|any|the|your|my|every|of|these|those|its)\s+)*(?:(?:previous|prior|above|earlier|preceding|original|initial|system|existing|old|current|safety)\s+)*{_TARGETS}", F), 0.75, "Asks the model to ignore its instructions"),
        (re.compile(r"\bforget (?:everything|all)(?: (?:you|that|from|above|before|previously)\b[^.\n]{0,30})?", F), 0.55, "Asks the model to forget its context"),
        (re.compile(r"\b(?:new|updated|real|actual|true)\s+(?:system\s+)?(?:instructions?|rules|directives?|task)\s*[:\-]", F), 0.55, "Declares replacement instructions"),
        (re.compile(r"\b(?:from now on|starting now|for the rest of (?:this|the) conversation|henceforth),?\s+(?:you|your|act|respond|answer|ignore)", F), 0.35, "Re-programs the assistant for the rest of the session"),
        (re.compile(r"(?:تجاهل|انس|اهمل|تخط|تجاوز|الغ)\s*(?:كل|جميع|كافة)?\s*(?:ال)?(?:تعليمات|اوامر|قواعد|قيود|ارشادات|توجيهات)(?:\s*(?:ال)?(?:سابقة|السابقه|اعلاه))?", F), 0.75, "يطلب تجاهل التعليمات / Arabic instruction override"),
        (re.compile(r"(?:من الان فصاعدا|ابتداء من الان|من هذه اللحظة)", F), 0.35, "Arabic session re-programming"),
    ],
    "role_hijack": [
        (re.compile(r"\b(?:DAN|AIM|STAN|DUDE)\b(?=[\s:,.!)])", re.MULTILINE), 0.45, "Known jailbreak persona name"),
        (re.compile(r"\b(?:do anything now|developer mode|dev mode|jailbr(?:ea|o)k(?:en)?|god mode|unfiltered mode|evil mode|sudo mode|chaos mode|opposite mode)\b", F), 0.6, "Known jailbreak persona / mode"),
        (re.compile(r"\b(?:does not|doesn't|do not|don't|will not|won't) (?:care|give a damn) about (?:\w+\s){0,2}(?:ethics|ethical|morals?|moral|laws?|legal|rules|consequences|safety|guidelines|polic(?:y|ies)|offensive)", F), 0.5, "Persona that does not care about rules or ethics"),
        (re.compile(r"\b(?:can do anything|answer (?:any and all|any|every|all) (?:questions?|prompts?|requests?)|respond to (?:any|every) (?:prompt|request|question))\b", F), 0.35, "Unconditional compliance"),
        (re.compile(r"\byou (?:have no|don't have any|do not have any|are not bound by|are free from|are not restricted by|are not limited by) (?:\w+\s){0,2}(?:rules|restrictions|limits|limitations|filters|guidelines|ethic\w*|morals?|boundaries|censorship)", F), 0.5, "Tells the model it has no limits"),
        (re.compile(r"\b(?:never|don't|do not|will not|won't|must not|shall not)\s+(?:ever\s+)?(?:say|respond with|reply with|include|use|mention|add|write)[^\n.]{0,40}?(?:i'?m sorry|i apologi[sz]e|as an ai|i cannot|i can't|disclaimers?|warnings?)", F), 0.5, "Forbids refusal / safety language"),
        (re.compile(r"\byou (?:are now|will now be|are going to (?:be|act as|pretend to be|play)|will act as|shall act as|now go by the name)\s+(?:an?\s+|the\s+)?[\"'“]?[A-Z][A-Za-z0-9]+", re.MULTILINE), 0.3, "Assigns the model a new persona"),
        (re.compile(r"\b(?:respond|answer|reply|act|speak)\s+(?:only\s+)?as (?:the character|both|two|[A-Z]{3,}\b)", re.MULTILINE), 0.3, "Dual / character response format"),
        (re.compile(r"\b(?:unfiltered|uncensored|unrestricted|amoral|unethical)\s+(?:ai|assistant|model|chatbot|version|mode|response)", F), 0.6, "Requests an unrestricted persona"),
        (re.compile(r"\b(?:without|no|free (?:from|of)|not bound by|ignore|regardless of|don't care about)\s+(?:any\s+)?(?:rules|restrictions|limits|limitations|filters|guidelines|ethic(?:s|al guidelines)|morals?|polic(?:y|ies)|censorship|content polic(?:y|ies))", F), 0.45, "Removes the model's limits"),
        (re.compile(r"\b(?:stay in character|never break character|never refuse|must not refuse|cannot refuse|can't refuse|will not refuse|do not refuse|answer without (?:any )?(?:warnings?|disclaimers?|filter)|no (?:warnings?|disclaimers?) (?:at all|whatsoever))\b", F), 0.5, "Forbids refusals"),
        (re.compile(r"\b(?:openai|anthropic|google)(?:'s)?\s+(?:content\s+)?polic(?:y|ies)\b", F), 0.35, "References provider content policy"),
        (re.compile(r"(?:وضع المطور|بدون قيود|بلا قيود|بدون اي قيود|دون قيود|لا تلتزم ب|غير مقيد|لا ترفض|بدون رقابة)", F), 0.55, "Arabic unrestricted-mode request"),
    ],
    "prompt_extraction": [
        (re.compile(r"\b(?:reveal|show|print|output|repeat|display|tell me|give me|leak|dump|disclose|recite|spell out|write out)\s+(?:me\s+)?(?:all\s+)?(?:of\s+)?(?:your|the)\s+(?:full\s+|entire\s+|exact\s+|original\s+)?(?:system\s+prompt|system\s+message|hidden\s+(?:prompt|instructions?)|initial\s+(?:prompt|instructions?)|instructions?|configuration|developer\s+(?:message|prompt)|pre-?prompt|guidelines|rules)", F), 0.7, "Tries to extract hidden instructions"),
        (re.compile(r"\bwhat (?:is|are|were) your (?:system prompt|instructions|initial instructions|rules|hidden instructions)", F), 0.6, "Asks for the system prompt"),
        (re.compile(r"(?:اكشف|اعرض|اطبع|كرر|اعطني|ما هي)\s*(?:لي)?\s*(?:تعليماتك|التعليمات المخفية|موجه النظام|البرومبت|تعليمات النظام|اوامرك الاصلية)", F), 0.7, "Arabic system-prompt extraction"),
    ],
    "guardrail_bypass": [
        (re.compile(r"\b(?:disable|turn off|deactivate|bypass|circumvent|evade|switch off|remove|ignore|skip|get around)\s+(?:the\s+|your\s+|all\s+|any\s+)?(?:security|safety|content|privacy)?\s*(?:filters?|guardrails?|safeguards?|moderation|redaction|masking|anonymi[sz]ation|security(?: layer| checks?| controls?)?|safety(?: checks?| features?)?|protections?|dlp|aegis|censorship)\b", F), 0.7, "Asks to disable a safeguard"),
        (re.compile(r"\b(?:unredacted|unmasked|uncensored|raw|full)\s+(?:data|file|records|version|output|pii)\b", F), 0.3, "Requests unredacted data"),
        (re.compile(r"(?:عطل|اوقف|تجاوز|الغ|ازل|تخطى|تخط)\s*(?:ال)?(?:حماية|فلتر|فلاتر|رقابة|اخفاء البيانات|تشفير|قيود الامنية|طبقة الامان|الحجب)", F), 0.7, "Arabic safeguard bypass"),
        (re.compile(r"(?:بدون|من غير)\s*(?:حذف|اخفاء|تعديل|حجب)", F), 0.35, "Arabic: without redaction"),
    ],
    "data_exfiltration": [
        (re.compile(r"\b(?:send|forward|post|upload|email|exfiltrate|transmit|leak|submit|copy)\b[^\n]{0,60}?\b(?:to|at|into)\s+(?:https?://|www\.|[\w.\-]+@[\w.\-]+\.\w+|(?:this|that|the following|my|our)\s+(?:url|address|endpoint|webhook|server|link|email))", F), 0.65, "Sends data to an external destination"),
        (re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*=", F), 0.7, "Markdown image URL carrying data (exfiltration)"),
        (re.compile(r"\b(?:give|tell|show|reveal|list|print|send|dump|output|share)\b[^\n.]{0,30}?\b(?:all\s+)?(?:the\s+|your\s+|stored\s+|saved\s+)?(?:passwords?|api[ _]keys?|credentials|access tokens?|secrets?|private keys?|session cookies?)\b", F), 0.5, "Requests credentials or secrets"),
        (re.compile(r"(?:ارسل|حول|انشر|ارفع|صدر)[^\n]{0,50}?(?:الى|ل)\s*(?:https?://|الرابط|رابط|البريد|بريد|الخادم)", F), 0.65, "Arabic exfiltration to external destination"),
        (re.compile(r"(?:اعطني|اعرض|اطبع|ارسل|شارك)[^\n.]{0,30}?(?:كلمات المرور|كلمة المرور|كلمات السر|المفاتيح|مفاتيح|التوكن|بيانات الدخول)", F), 0.5, "Arabic credential request"),
    ],
    "indirect_marker": [
        (re.compile(r"\b(?:if you are|attention|note to|instructions? (?:for|to)|message (?:for|to)|dear|hey)\s+(?:an?\s+|the\s+)?(?:ai|a\.i\.|assistant|llm|language model|chatbot|gpt|chatgpt|claude|gemini|copilot|agent)\b", F), 0.45, "Text addresses the AI model directly"),
        (re.compile(r"\b(?:ai|assistant|llm|model|agent)s?\s+(?:reading|processing|summari[sz]ing|analy[sz]ing|parsing) this\b", F), 0.45, "Text speaks to a model reading it"),
        (re.compile(r"\bwhen (?:you )?(?:summari[sz]e|process|read|translate|analy[sz]e)\s+(?:this|the following)\s+(?:document|email|page|text|file|message|content)", F), 0.4, "Conditional instruction for a model processing the text"),
        (re.compile(r"<!--[\s\S]{0,400}?(?:ignore|instruction|assistant|\bai\b|system|prompt)[\s\S]{0,400}?-->", F), 0.6, "Instruction hidden in an HTML comment"),
        (re.compile(r"\[(?:system|admin|developer|assistant|sys)\]|<\|?(?:system|im_start|im_end|endoftext|start_header_id)\|?>|^#{2,}\s*(?:system|instruction)s?\b|^\s*(?:system|developer)\s*(?:message|prompt)?\s*:", F), 0.55, "Fake system / chat-template markers"),
        (re.compile(r"(?:الى|يا)\s*(?:المساعد|الذكاء الاصطناعي|النموذج|الروبوت)|(?:عند|اذا)\s*(?:تلخيص|قراءة|معالجة|ترجمة)\s*(?:هذا|هذه)", F), 0.45, "Arabic text addressing the model"),
    ],
}
_CONTENT_BOOST = {"instruction_override": 1.15, "prompt_extraction": 1.1, "guardrail_bypass": 1.1, "data_exfiltration": 1.15,
                  "role_hijack": 1.0, "indirect_marker": 1.35}
_FAMILY_TEXT = {
    "instruction_override": "tries to override the model's instructions",
    "role_hijack": "tries to switch the model into an unrestricted persona",
    "prompt_extraction": "tries to extract hidden or system instructions",
    "guardrail_bypass": "asks to disable a safeguard",
    "data_exfiltration": "tries to move data or secrets to an external place",
    "indirect_marker": "contains text addressed to an AI model",
    "obfuscation": "hides content with encoding or invisible characters",
}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SPACED = re.compile(r"\b(?:[A-Za-z][\s._\-]){4,}[A-Za-z]\b")
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=])")


def _decoded_views(text: str) -> list[tuple[str, str]]:
    views = []
    joined = _SPACED.sub(lambda m: re.sub(r"[\s._\-]", "", m.group(0)), text)
    if joined != text:
        views.append(("spaced-out letters", joined))
    if re.search(r"[a-z][0-9@$][a-z]", text, re.I):
        leet = text.translate(_LEET)
        if leet != text:
            views.append(("leetspeak", leet))
    for m in _B64.finditer(text):
        blob = m.group(0)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if sum(c.isprintable() for c in dec) >= 0.9 * len(dec) and re.search(r"[A-Za-z؀-ۿ]{3,}", dec):
            views.append(("base64", dec))
    return views


class InjectionDetector:
    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def _scan(self, text: str, segment: str) -> list[InjectionSignal]:
        signals: list[InjectionSignal] = []
        if not text:
            return signals
        nt = normalize(text)
        views = [("", nt.text)] + _decoded_views(nt.text)
        for view_name, view in views:
            for family, sigs in SIGNATURES.items():
                for rx, w, why in sigs:
                    m = rx.search(view)
                    if not m:
                        continue
                    if view_name:
                        s, e, ev = 0, len(text), f"{why} (revealed after decoding {view_name})"
                        signals.append(InjectionSignal(family="obfuscation", segment=segment, weight=0.35, evidence=f"Obfuscated payload ({view_name})", start=s, end=e))
                    else:
                        s, e = nt.span(m.start(), m.end())
                        ev = why
                    if segment == "content":
                        w = min(0.95, w * _CONTENT_BOOST[family])
                    signals.append(InjectionSignal(family=family, segment=segment, weight=round(w, 3), evidence=ev, start=s, end=e))
        if nt.invisible_count >= 3:
            signals.append(InjectionSignal(family="obfuscation", segment=segment, weight=0.3,
                                           evidence=f"{nt.invisible_count} invisible / bidi-control characters", start=0, end=len(text)))
        return signals

    def scan(self, prompt: str, content: Optional[str] = None) -> InjectionResult:
        signals = self._scan(prompt, "prompt") + self._scan(content or "", "content")
        fam_best: dict[str, list[float]] = {}
        for s in signals:
            fam_best.setdefault(s.family, []).append(s.weight)
        score = 1.0
        for fam, ws in fam_best.items():
            ws.sort(reverse=True)
            w = min(0.95, ws[0] + 0.1 * (len(ws) - 1))
            score *= 1 - w
        score = round(1 - score, 3) if signals else 0.0
        sev = Severity.CRITICAL if score >= 0.85 else Severity.HIGH if score >= 0.65 else Severity.MEDIUM if score >= 0.4 else Severity.LOW
        detected = score >= self.threshold
        direct = any(s.segment == "prompt" and s.family != "indirect_marker" for s in signals)
        indirect = any(s.segment == "content" for s in signals)
        if signals:
            fams = sorted(fam_best, key=lambda f: -max(fam_best[f]))
            where = "in supplied content (indirect)" if indirect and not direct else ("in the prompt and supplied content" if indirect else "in the prompt")
            expl = f"Score {score:.2f}: text {where} " + "; ".join(_FAMILY_TEXT[f] for f in fams[:3]) + "."
        else:
            expl = "No injection signals found."
        signals.sort(key=lambda s: -s.weight)
        return InjectionResult(score=score, severity=sev, detected=detected, direct=direct and detected, indirect=indirect and detected,
                               signals=signals[:12], explanation=expl)
