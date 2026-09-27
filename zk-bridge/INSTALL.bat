@echo off
chcp 65001 >nul
title تجهيز جسر البصمة
echo تثبيت الحزم المطلوبة لأول مرة ...
call npm install
echo.
echo تم التثبيت. الآن:
echo  1) انسخ config.example.json وسمّه config.json وعدّل القيم بداخله.
echo  2) ضع ملف serviceAccountKey.json (مفتاح خدمة Firebase) في نفس هذا المجلد.
echo  3) شغّل START.bat.
pause
