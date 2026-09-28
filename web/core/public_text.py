"""Texts for the player-facing pages (Russian by default, English on request)."""
from urllib.parse import urlsplit

from django.conf import settings

TEXT = {
    "ru": {
        "title": "Проверка Moon",
        "intro": "Официальная проверка ПК сервера MOON. Запускайте её, только когда администратор попросил и дал вам код проверки.",
        "compat": "Подходит ли ваш ПК",
        "compat_items": [
            "Windows 10 или 11 (64-бит), или Linux x86-64.",
            "Права администратора — без них проверка будет неполной, и администратор это увидит.",
            "Интернет-доступ к {host} для отправки результатов.",
            "Около 150 МБ свободного места. Ничего не устанавливается и не остаётся после закрытия.",
        ],
        "steps": "Как пройти проверку",
        "step_items": [
            "Скачайте архив (кнопка выше) и распакуйте его (папка runtime должна лежать рядом с MoonCheck.exe).",
            "Правый клик по MoonCheck.exe → «Запуск от имени администратора». Если Windows SmartScreen предупредит — «Подробнее» → «Выполнить в любом случае».",
            "Введите код от администратора. Проверьте, что показан ник именно вашего администратора.",
            "Нажмите «Начать проверку» и не закрывайте окно, пока не увидите «Результаты доставлены».",
        ],
        "collected": "Что отправляется и что нет",
        "collected_items": [
            "Отправляется: найденные совпадения (пути файлов, названия программ, следы запуска), имя ПК, пользователь Windows, найденные Steam-аккаунты, сведения о самой проверке.",
            "Не отправляется: содержимое ваших файлов, переписка, пароли. История браузера проверяется на ПК — уходят только совпадения с сайтами читов.",
            "Результаты видит только администратор, выдавший код, и старшие администраторы. Хранятся ограниченный срок и затем удаляются.",
        ],
        "after": "После проверки",
        "after_text": "Чекер покажет вашу личную ссылку на страницу проверки. Там видно решение администратора, можно скачать свой отчёт, запросить удаление данных или подать апелляцию — её рассматривает другой администратор.",
        "download": "Скачать",
        "none_yet": "Сборка ещё не опубликована. Обратитесь к администратору.",
        "switch": "English",
    },
    "en": {
        "title": "Moon Check",
        "intro": "The official PC check of the MOON server. Run it only when an admin asks you to and gives you a check code.",
        "compat": "Will it work on your PC",
        "compat_items": [
            "Windows 10 or 11 (64-bit), or Linux x86-64.",
            "Administrator rights — without them the check is incomplete, and the admin sees that.",
            "Internet access to {host} to send the results.",
            "About 150 MB of free space. Nothing is installed and nothing stays after you close it.",
        ],
        "steps": "How to take the check",
        "step_items": [
            "Download the archive (button above) and unzip it (keep the runtime folder next to MoonCheck.exe).",
            "Right-click MoonCheck.exe → Run as administrator. If Windows SmartScreen warns, choose More info → Run anyway.",
            "Enter the code from your admin. Make sure the alias shown is your admin's.",
            "Press Start check and keep the window open until it says the results were delivered.",
        ],
        "collected": "What is sent — and what is not",
        "collected_items": [
            "Sent: matches found (file paths, program names, execution traces), PC name, Windows user name, Steam accounts found, and details about the check itself.",
            "Not sent: the contents of your files, messages, passwords. Browser history is checked on your PC — only matches with cheat sites leave it.",
            "Only the admin who gave you the code and senior admins see the results. They are kept for a limited time, then deleted.",
        ],
        "after": "After the check",
        "after_text": "The checker shows your private link to this check. There you see the admin's decision, can download your report, ask for your data to be deleted, or file an appeal — a different admin reviews it.",
        "download": "Download",
        "none_yet": "No build has been published yet. Ask your admin.",
        "switch": "Русский",
    },
}


PLAYER = {
    "ru": {
        "title": "Ваша проверка",
        "requested": "Проверку запросил администратор {admin} {when}.",
        "private": "Эта страница личная: её видит любой, у кого есть ссылка, поэтому не публикуйте её.",
        "test": "ТЕСТОВЫЙ ЗАПУСК — это не настоящая проверка.",
        "status": {"WAITING": "Ожидает запуска", "CONNECTED": "Чекер подключён", "SCANNING": "Идёт проверка",
                   "COMPLETED": "Завершена", "ABANDONED": "Прервана", "EXPIRED": "Код истёк",
                   "CANCELLED": "Отменена"},
        "outcome": {
            "VALIDATED_DETECTION": ("Найдено точное совпадение",
                                    "Файл на ПК побайтно совпал с известным читом. Решение принимает администратор."),
            "REVIEW_REQUIRED": ("Нужна проверка администратором",
                                "Найдены следы, которые должен посмотреть администратор. Само по себе это не обвинение."),
            "UNSUPPORTED_CONFIGURATION": ("Система не поддерживается",
                                          "Проверка не рассчитана на вашу систему, поэтому её результат неполный."),
            "INCOMPLETE_SCAN": ("Проверка неполная",
                                "Часть обязательных проверок не выполнилась (например, без прав администратора). "
                                "Администратор может попросить пройти её снова."),
            "NO_EVIDENCE": ("Ничего не найдено", "Все обязательные проверки прошли и ничего не нашли."),
        },
        "decision": "Решение",
        "decisions": {"CLEARED": "Чисто", "BANNED": "Бан", "REVIEW": "Нужна ещё одна проверка",
                      "RECHECK": "Нужно пройти проверку заново"},
        "no_decision": "Решения пока нет. Администратор изучит результаты и запишет решение — оно появится здесь.",
        "vcode": "Код подтверждения",
        "vcode_help": "тот же код был на вашем экране в конце проверки.",
        "abandoned": "Чекер перестал отвечать до отправки результатов. Свяжитесь с администратором.",
        "running": "Проверка ещё не закончена. Не закрывайте чекер, пока он не напишет, что результаты доставлены.",
        "refresh": "Обновить",
        "data": "Ваши данные",
        "data_text": "В отчёте — найденные совпадения, имя ПК и пользователя Windows, найденные Steam-аккаунты. "
                     "Отчёт хранится {days} дн., затем удаляется.",
        "export": "Скачать мой отчёт (JSON)",
        "delete_ask": "Запросить удаление",
        "delete_note": "Запрос рассматривает администратор. Данные, связанные с действующим баном, могут быть "
                       "сохранены — с указанием причины.",
        "delete_send": "Отправить запрос на удаление",
        "delete_waiting": "Ваш запрос на удаление ждёт администратора.",
        "delete_sent": "Запрос на удаление отправлен.",
        "appeals": "Апелляции",
        "appeal_n": "Апелляция №{n}",
        "appeal_status": {"OPEN": "На рассмотрении", "UPHELD": "Решение оставлено", "OVERTURNED": "Решение отменено",
                          "RECHECK": "Назначена повторная проверка"},
        "answer": "Ответ",
        "no_appeals": "Апелляций нет.",
        "appeal_new": "Подать апелляцию",
        "appeal_who": "Её рассматривает другой администратор — не тот, кто принял решение.",
        "appeal_send": "Отправить апелляцию",
        "appeal_sent": "Апелляция отправлена. Ответ появится на этой странице.",
        "appeal_later": "Апелляцию можно подать после того, как будет принято решение.",
        "appeal_limit": "Слишком много апелляций с вашего адреса. Попробуйте позже.",
        "f_statement": "Ваше объяснение",
        "f_statement_help": "Опишите, что, по-вашему, неверно. Если можете, ссылайтесь на номера улик (E1, E2…).",
        "f_contact": "Как с вами связаться? (Discord или Steam)",
        "f_reason": "Причина (необязательно)",
        "e_required": "Заполните это поле.",
        "e_short": "Слишком коротко: нужно не меньше {n} символов.",
        "e_long": "Слишком длинно: не больше {n} символов.",
    },
    "en": {
        "title": "Your check",
        "requested": "Requested by admin {admin} on {when}.",
        "private": "This page is private: anyone with its link can see it, so do not share it.",
        "test": "TEST RUN — not a real check.",
        "status": {"WAITING": "Waiting to start", "CONNECTED": "Checker connected", "SCANNING": "Checking",
                   "COMPLETED": "Completed", "ABANDONED": "Interrupted", "EXPIRED": "Code expired",
                   "CANCELLED": "Cancelled"},
        "outcome": {
            "VALIDATED_DETECTION": ("Exact match found",
                                    "A file on the PC matched a known cheat byte for byte. An admin makes the decision."),
            "REVIEW_REQUIRED": ("Admin review needed",
                                "Traces were found that an admin needs to look at. This is not an accusation on its own."),
            "UNSUPPORTED_CONFIGURATION": ("System not supported",
                                          "The check is not built for your system, so its result is incomplete."),
            "INCOMPLETE_SCAN": ("Check incomplete",
                                "Some required checks did not run (for example without administrator rights). "
                                "The admin may ask you to run it again."),
            "NO_EVIDENCE": ("Nothing found", "Every required check ran and found nothing."),
        },
        "decision": "Decision",
        "decisions": {"CLEARED": "Cleared", "BANNED": "Banned", "REVIEW": "Needs another review",
                      "RECHECK": "Re-check required"},
        "no_decision": "No decision yet. The admin reviews the results and records one; it will appear here.",
        "vcode": "Verification code",
        "vcode_help": "the same code was on your screen when the check finished.",
        "abandoned": "The checker stopped reporting before the results were sent. Contact the admin.",
        "running": "The check is not finished yet. Keep the checker open until it says the results were delivered.",
        "refresh": "Refresh",
        "data": "Your data",
        "data_text": "The report holds the matches found, your PC name and Windows user name, and the Steam accounts "
                     "found. It is kept for {days} days, then deleted.",
        "export": "Download my report (JSON)",
        "delete_ask": "Ask for deletion",
        "delete_note": "An admin handles the request. Data tied to an active ban may be kept, with the reason recorded.",
        "delete_send": "Send deletion request",
        "delete_waiting": "Your deletion request is waiting for an admin.",
        "delete_sent": "Deletion request sent.",
        "appeals": "Appeals",
        "appeal_n": "Appeal #{n}",
        "appeal_status": {"OPEN": "Under review", "UPHELD": "Decision upheld", "OVERTURNED": "Decision overturned",
                          "RECHECK": "Re-check ordered"},
        "answer": "Answer",
        "no_appeals": "No appeals.",
        "appeal_new": "File an appeal",
        "appeal_who": "A different admin — not the one who decided — reviews it.",
        "appeal_send": "Send appeal",
        "appeal_sent": "Appeal sent. The answer will appear on this page.",
        "appeal_later": "You can appeal once a decision is recorded.",
        "appeal_limit": "Too many appeals from your address. Try again later.",
        "f_statement": "Your statement",
        "f_statement_help": "Explain what you believe is wrong. Refer to evidence ids (E1, E2…) if you can.",
        "f_contact": "How can the admins reach you? (Discord or Steam)",
        "f_reason": "Reason (optional)",
        "e_required": "This field is required.",
        "e_short": "Too short: at least {n} characters.",
        "e_long": "Too long: at most {n} characters.",
    },
}

ERRORS = {
    "ru": {"csrf": ("Форма устарела", "Обновите страницу и попробуйте снова."),
           "404": ("Страница не найдена", "Ссылка неверна или устарела. Если это ссылка на вашу проверку, "
                                          "возьмите её у чекера или администратора ещё раз."),
           "403": ("Нет доступа", "Это действие недоступно.")},
    "en": {"csrf": ("Form expired", "Reload the page and try again."),
           "404": ("Not found", "The link is wrong or no longer valid. If it is the link to your check, "
                                "get it again from the checker or the admin."),
           "403": ("Not allowed", "This action is not available.")},
}


def language(request):
    """?lang= wins, then the browser's first preference; Russian otherwise (the server's players)."""
    lang = request.GET.get("lang")
    if lang in TEXT:
        return lang
    return "en" if request.headers.get("Accept-Language", "").lower().startswith("en") else "ru"


def pick(request):
    lang = language(request)
    host = urlsplit(settings.PUBLIC_URL).hostname or "localhost"
    t = dict(TEXT[lang])
    t["compat_items"] = [item.format(host=host) for item in t["compat_items"]]
    return lang, t


def is_public_path(path):
    return path.startswith(("/p/", "/download"))
