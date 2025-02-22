# סיכום למבחן על פרוטוקול HTTP

## חלק 1 - בקשה ותגובה
- **HTTP (HyperText Transfer Protocol)** שייך לשכבת האפליקציה ומשמש לגלישה באינטרנט.
- **URL (Universal Resource Locator)** מזהה ייחודי לכל דף אינטרנט.
- **מבנה תקשורת HTTP**:
  - **בקשה (Request)**: הלקוח שולח בקשה לשרת, בדרך כלל עם מתודת `GET`.
  - **תגובה (Response)**: השרת מחזיר נתונים, כולל קוד סטטוס כמו `200 OK`.
  - **Headers**: מידע נוסף שנשלח יחד עם הבקשה או התגובה.

## חלק 2 - סטטוסים ומתודות
- **קודי סטטוס נפוצים**:
  - `200 OK` – הבקשה הצליחה.
  - `302 Found` – הפניה מחדש.
  - `404 Not Found` – הדף המבוקש לא נמצא.
- **מתודות HTTP**:
  - `GET` – בקשת נתונים מהשרת.
  - `POST` – שליחת נתונים לשרת.
  - `HEAD` – דומה ל-`GET`, אך מחזיר רק את הכותרות ללא התוכן.

## חלק 3 - מטמון (Cache)
- **מטרת המטמון**:
  - חיסכון בזמן ובמשאבים על ידי שמירת דפי אינטרנט מקומיים.
  - טעינה מהירה יותר אם הדף לא השתנה.
- **בקשת `GET` מותנית**:
  - הדפדפן שולח את זמן השמירה האחרון (`If-Modified-Since`).
  - השרת מחזיר `304 Not Modified` אם אין שינוי.

## חלק 4 - בקשת GET עם פרמטרים
- **שימוש בפרמטרים ב-URL**:
  - הוספת פרמטרים אחרי `?`, לדוגמה:  
    ```url
    https://www.google.com/search?q=israel
    ```
  - ניתן להעביר מספר פרמטרים, מופרדים ב-`&`.


