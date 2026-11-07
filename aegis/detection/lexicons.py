"""Bilingual (English / Arabic) lexicons used by the recognizers.

Values are canonical keys (``value_norm``) shared with the population model in
``aegis/exposure/population.py``, so a detected "جدة" and "Jeddah" both count as
the same attribute value when measuring identifiability.

These lists are deliberately general (common Saudi-workplace vocabulary). They
are NOT derived from the evaluation datasets.
"""

# canonical city -> (region, english aliases, arabic aliases)
CITIES: dict[str, tuple[str, list[str], list[str]]] = {
    "riyadh": ("central", ["Riyadh"], ["الرياض"]),
    "jeddah": ("western", ["Jeddah", "Jedda", "Jiddah"], ["جدة", "جده"]),
    "makkah": ("western", ["Makkah", "Mecca", "Makka"], ["مكة", "مكه", "مكة المكرمة"]),
    "madinah": ("western", ["Madinah", "Medina", "Madina"], ["المدينة المنورة", "المدينه المنوره"]),
    "taif": ("western", ["Taif", "Al Taif"], ["الطائف"]),
    "dammam": ("eastern", ["Dammam"], ["الدمام"]),
    "khobar": ("eastern", ["Khobar", "Al Khobar", "Alkhobar"], ["الخبر"]),
    "dhahran": ("eastern", ["Dhahran"], ["الظهران"]),
    "jubail": ("eastern", ["Jubail"], ["الجبيل"]),
    "ahsa": ("eastern", ["Al Ahsa", "Hofuf", "Al-Ahsa"], ["الاحساء", "الهفوف"]),
    "abha": ("southern", ["Abha"], ["ابها"]),
    "jazan": ("southern", ["Jazan", "Jizan"], ["جازان", "جيزان"]),
    "najran": ("southern", ["Najran"], ["نجران"]),
    "tabuk": ("northern", ["Tabuk"], ["تبوك"]),
    "hail": ("northern", ["Hail", "Ha'il"], ["حائل"]),
    "buraidah": ("central", ["Buraidah", "Buraydah", "Qassim"], ["بريدة", "القصيم"]),
    "alula": ("northern", ["AlUla", "Al Ula", "Al-Ula"], ["العلا"]),
    "neom": ("northern", ["NEOM"], ["نيوم"]),
}

REGION_LABELS = {
    "central": ("Central Region", "المنطقة الوسطى"),
    "western": ("Western Region", "المنطقة الغربية"),
    "eastern": ("Eastern Region", "المنطقة الشرقية"),
    "southern": ("Southern Region", "المنطقة الجنوبية"),
    "northern": ("Northern Region", "المنطقة الشمالية"),
}

# canonical department -> (function group, english aliases, arabic aliases)
DEPARTMENTS: dict[str, tuple[str, list[str], list[str]]] = {
    "finance": ("corporate", ["Finance", "Finance department", "Accounting"], ["المالية", "الادارة المالية", "المحاسبة"]),
    "hr": ("corporate", ["HR", "Human Resources", "People team"], ["الموارد البشرية"]),
    "legal": ("corporate", ["Legal", "Legal department"], ["الشؤون القانونية", "القانونية"]),
    "procurement": ("corporate", ["Procurement", "Purchasing"], ["المشتريات"]),
    "internal_audit": ("corporate", ["Internal Audit"], ["المراجعة الداخلية", "التدقيق الداخلي"]),
    "compliance": ("corporate", ["Compliance"], ["الالتزام", "الامتثال"]),
    "strategy": ("corporate", ["Strategy", "Strategy office"], ["الاستراتيجية"]),
    "it": ("technology", ["IT", "Information Technology"], ["تقنية المعلومات"]),
    "cybersecurity": ("technology", ["Cybersecurity", "Cyber Security", "Information Security", "InfoSec"], ["الامن السيبراني", "امن المعلومات"]),
    "data_ai": ("technology", ["Data & AI", "Data and AI", "Data Science", "Analytics"], ["البيانات والذكاء الاصطناعي", "علم البيانات"]),
    "rnd": ("technology", ["R&D", "Research and Development"], ["البحث والتطوير"]),
    "marketing": ("commercial", ["Marketing"], ["التسويق"]),
    "sales": ("commercial", ["Sales"], ["المبيعات"]),
    "customer_service": ("commercial", ["Customer Service", "Customer Care", "Support team"], ["خدمة العملاء"]),
    "operations": ("operations", ["Operations", "Ops"], ["العمليات"]),
    "logistics": ("operations", ["Logistics", "Supply Chain"], ["الخدمات اللوجستية", "سلسلة الامداد"]),
}

FUNCTION_LABELS = {
    "corporate": ("a corporate function", "إدارة مساندة"),
    "technology": ("a technology function", "إدارة تقنية"),
    "commercial": ("a commercial function", "إدارة تجارية"),
    "operations": ("an operations function", "إدارة تشغيلية"),
}

# canonical title -> (level, english aliases, arabic aliases). Longest match wins.
JOB_TITLES: dict[str, tuple[str, list[str], list[str]]] = {
    "intern": ("staff", ["intern", "trainee"], ["متدرب", "متدربة"]),
    "analyst": ("staff", ["analyst"], ["محلل", "محللة"]),
    "specialist": ("staff", ["specialist"], ["اخصائي", "اخصائية"]),
    "senior_specialist": ("staff", ["senior specialist", "senior analyst"], ["اخصائي اول", "اخصائية اولى", "محلل اول"]),
    "engineer": ("staff", ["engineer", "developer"], ["مهندس", "مهندسة", "مطور", "مطورة"]),
    "senior_engineer": ("staff", ["senior engineer", "senior developer"], ["مهندس اول", "مهندسة اولى", "مطور اول"]),
    "team_lead": ("management", ["team lead", "team leader", "supervisor"], ["قائد فريق", "قائدة فريق", "مشرف", "مشرفة"]),
    "manager": ("management", ["manager"], ["مدير", "مديرة"]),
    "senior_manager": ("management", ["senior manager"], ["مدير اول", "مديرة اولى"]),
    "director": ("executive", ["director", "head of department", "general manager"], ["مدير ادارة", "مديرة ادارة", "مدير عام", "رئيس قسم"]),
    "vp": ("executive", ["vice president", "VP"], ["نائب الرئيس", "نائبة الرئيس"]),
    "chief": ("executive", ["CEO", "CFO", "CTO", "CIO", "CISO", "chief executive", "chief financial officer"], ["الرئيس التنفيذي", "الرئيسة التنفيذية"]),
}

LEVEL_LABELS = {
    "staff": ("a staff-level employee", "موظف"),
    "management": ("a manager-level employee", "موظف بمستوى إداري"),
    "executive": ("an executive", "قيادي"),
}

# canonical nationality -> (group, english, arabic)
NATIONALITIES: dict[str, tuple[str, list[str], list[str]]] = {
    "saudi": ("gcc", ["Saudi"], ["سعودي", "سعودية"]),
    "emirati": ("gcc", ["Emirati"], ["اماراتي", "اماراتية"]),
    "kuwaiti": ("gcc", ["Kuwaiti"], ["كويتي", "كويتية"]),
    "egyptian": ("arab", ["Egyptian"], ["مصري", "مصرية"]),
    "jordanian": ("arab", ["Jordanian"], ["اردني", "اردنية"]),
    "sudanese": ("arab", ["Sudanese"], ["سوداني", "سودانية"]),
    "yemeni": ("arab", ["Yemeni"], ["يمني", "يمنية"]),
    "syrian": ("arab", ["Syrian"], ["سوري", "سورية"]),
    "moroccan": ("arab", ["Moroccan"], ["مغربي", "مغربية"]),
    "indian": ("asian", ["Indian"], ["هندي", "هندية"]),
    "pakistani": ("asian", ["Pakistani"], ["باكستاني", "باكستانية"]),
    "filipino": ("asian", ["Filipino", "Filipina"], ["فلبيني", "فلبينية"]),
    "british": ("western", ["British"], ["بريطاني", "بريطانية"]),
    "american": ("western", ["American"], ["امريكي", "امريكية"]),
}

NATIONALITY_GROUP_LABELS = {
    "gcc": ("a GCC national", "من مواطني الخليج"),
    "arab": ("an Arab national", "من جنسية عربية"),
    "asian": ("an Asian national", "من جنسية آسيوية"),
    "western": ("a Western national", "من جنسية غربية"),
}

GENDER_TERMS = {
    "female": (["female", "woman", "she", "her"], ["امراة", "انثى", "موظفة", "زميلتي", "هي"]),
    "male": (["male", "man", "he", "his", "him"], ["رجل", "ذكر", "هو", "زميلي"]),
}

HONORIFICS_EN = ["Mr", "Mrs", "Ms", "Miss", "Dr", "Eng", "Prof", "Sheikh", "Mr.", "Mrs.", "Ms.", "Dr.", "Eng.", "Prof."]
HONORIFICS_AR = ["الاستاذ", "الاستاذة", "المهندس", "المهندسة", "الدكتور", "الدكتورة", "د.", "م.", "ا.", "السيد", "السيدة",
                 "الموظف", "الموظفة", "الزميل", "الزميلة", "العميل", "العميلة", "المريض", "المريضة"]
NAME_CUES_EN = ["named", "called", "employee", "colleague", "customer", "client", "manager", "candidate", "patient", "applicant"]
NAME_CUES_AR = ["اسمه", "اسمها", "يدعى", "تدعى", "زميلي", "زميلتي", "موظفنا", "موظفتنا"]

# Common given names (romanized and Arabic). Used as name *evidence*, combined
# with a following capitalized / Arabic word for the surname.
FIRST_NAMES_EN = [
    "Mohammed", "Muhammad", "Mohamed", "Ahmed", "Ahmad", "Abdullah", "Abdulrahman", "Abdulaziz", "Khalid", "Khaled",
    "Fahad", "Fahd", "Faisal", "Sultan", "Saud", "Turki", "Nasser", "Omar", "Umar", "Ali", "Hassan", "Hussein",
    "Ibrahim", "Yousef", "Youssef", "Saleh", "Salman", "Majed", "Majid", "Bandar", "Nawaf", "Mishal", "Rakan",
    "Hamad", "Hamza", "Ziyad", "Ziad", "Waleed", "Walid", "Tariq", "Tarek", "Yasser", "Mansour", "Mazen", "Adel",
    "Fatimah", "Fatima", "Noura", "Nora", "Sara", "Sarah", "Reem", "Rim", "Lama", "Hessa", "Haifa", "Amal",
    "Maha", "Mona", "Muna", "Hind", "Asma", "Aisha", "Aishah", "Maryam", "Mariam", "Khadija", "Layla", "Leila",
    "Lina", "Dana", "Rawan", "Shahad", "Joud", "Ghada", "Nouf", "Abeer", "Areej", "Alanoud", "Wejdan", "Ibtissam",
    "John", "James", "Michael", "David", "Robert", "William", "Richard", "Thomas", "Daniel", "Paul", "Mark", "Peter",
    "Mary", "Jennifer", "Linda", "Elizabeth", "Susan", "Jessica", "Emily", "Emma", "Olivia", "Anna", "Maria",
    "Priya", "Rahul", "Amit", "Ravi", "Arjun", "Imran", "Bilal", "Usman", "Jose", "Juan", "Carlos",
]
FIRST_NAMES_AR = [
    "محمد", "احمد", "عبدالله", "عبدالرحمن", "عبدالعزيز", "خالد", "فهد", "فيصل", "سلطان", "سعود", "تركي", "ناصر",
    "عمر", "علي", "حسن", "حسين", "ابراهيم", "يوسف", "صالح", "سلمان", "ماجد", "بندر", "نواف", "مشعل", "راكان",
    "حمد", "حمزة", "زياد", "وليد", "طارق", "ياسر", "منصور", "مازن", "عادل", "سامي", "هشام", "بدر", "نايف",
    "فاطمة", "نورة", "سارة", "ريم", "لمى", "حصة", "هيفاء", "امل", "مها", "منى", "هند", "اسماء", "عائشة",
    "مريم", "خديجة", "ليلى", "لينا", "دانة", "روان", "شهد", "جود", "غادة", "نوف", "عبير", "اريج", "العنود",
    "وجدان", "ابتسام", "رهف", "رنا", "هيا", "الجوهرة", "بشاير", "اثير", "شوق", "منيرة", "لطيفة", "نجلاء",
]

CONFIDENTIAL_MARKERS_EN = [
    "confidential", "strictly confidential", "internal only", "internal use only", "not for distribution",
    "do not share", "do not forward", "under nda", "under embargo", "restricted", "top secret", "classified",
    "privileged and confidential", "for internal use",
]
CONFIDENTIAL_MARKERS_AR = [
    "سري", "سري للغاية", "سري جدا", "للاستخدام الداخلي", "داخلي فقط", "لا ينشر", "لا يعمم", "غير قابل للنشر",
    "مقيد", "محظور النشر",
]

BUSINESS_SENSITIVE_EN = [
    "acquisition", "merger", "layoff", "layoffs", "restructuring plan", "unreleased product", "earnings before announcement",
    "unannounced", "pricing strategy", "bid price", "tender price", "board decision", "board minutes", "due diligence",
    "salary scale", "termination list", "investigation report", "security incident", "data breach", "vulnerability report",
    "source code", "trade secret", "roadmap",
]
BUSINESS_SENSITIVE_AR = [
    "استحواذ", "اندماج", "تسريح", "اعادة الهيكلة", "منتج غير معلن", "استراتيجية التسعير", "سعر المناقصة", "قرار مجلس الادارة",
    "محضر مجلس الادارة", "الفحص النافي للجهالة", "سلم الرواتب", "قائمة انهاء الخدمات", "تقرير التحقيق", "حادثة امنية",
    "تسرب بيانات", "ثغرة امنية", "الكود المصدري", "سر تجاري", "خارطة الطريق",
]

SALARY_CUES_EN = ["salary", "salaries", "compensation", "bonus", "pay", "paid", "earns", "wage", "allowance", "package"]
SALARY_CUES_AR = ["راتب", "راتبه", "راتبها", "رواتب", "مكافاة", "بدل", "اجر", "يتقاضى", "تتقاضى", "الراتب"]

DOB_CUES_EN = ["born", "date of birth", "dob", "birthday", "birth date"]
DOB_CUES_AR = ["مواليد", "تاريخ الميلاد", "ولد", "ولدت", "تاريخ ميلاد"]

# Tabular header synonyms -> entity type
HEADER_TYPES: dict[str, str] = {
    "name": "person_name", "full_name": "person_name", "customer_name": "person_name", "employee_name": "person_name",
    "first_name": "person_name", "last_name": "person_name", "الاسم": "person_name", "اسم": "person_name", "اسم العميل": "person_name",
    "email": "email", "e-mail": "email", "البريد": "email", "البريد الالكتروني": "email",
    "phone": "phone", "mobile": "phone", "phone_number": "phone", "الجوال": "phone", "الهاتف": "phone", "رقم الجوال": "phone",
    "national_id": "national_id", "nid": "national_id", "iqama": "national_id", "id_number": "national_id", "رقم الهوية": "national_id", "الهوية": "national_id",
    "iban": "iban", "card_number": "payment_card", "card": "payment_card",
    "age": "age", "العمر": "age", "عمر": "age",
    "city": "city", "المدينة": "city", "location": "city", "office": "city",
    "department": "department", "dept": "department", "القسم": "department", "الادارة": "department",
    "title": "job_title", "job_title": "job_title", "position": "job_title", "المسمى": "job_title", "المسمى الوظيفي": "job_title",
    "nationality": "nationality", "الجنسية": "nationality",
    "gender": "gender", "الجنس": "gender",
    "salary": "salary", "الراتب": "salary", "amount": "money_amount", "المبلغ": "money_amount", "price": "money_amount",
    "dob": "date_of_birth", "date_of_birth": "date_of_birth", "birth_date": "date_of_birth", "تاريخ الميلاد": "date_of_birth",
    "date": "date", "التاريخ": "date", "address": "address", "العنوان": "address", "join_year": "join_year",
}
