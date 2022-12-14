@ECHO OFF
IF "%PROCESSOR_ARCHITECTURE%"=="x86" (set sd=sdelete.exe) else (set sd=sdelete64.exe)
for %%p in (a b c d e f g h i j k l m n o p q r s t u v w x y z) do if exist %%p:\nul %sd% -p 1 -z %%p: /accepteula
