' ReadValidationResult.vbs
Dim fso, ts, value
Set fso = CreateObject("Scripting.FileSystemObject")
Set ts = fso.OpenTextFile("C:\ProgramData\MyApp\Logs\ValidationResult.txt", 1)
value = ts.ReadLine()
Session.Property("VALIDATION_FAILED") = value
ts.Close()
