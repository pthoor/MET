function Get-METAssessableMailboxes {
    [CmdletBinding()]
    param()

    $supportedTypes = @(
        'UserMailbox'
        'SharedMailbox'
        'RoomMailbox'
        'EquipmentMailbox'
        'GroupMailbox'
    )

    @(
        Get-EXOMailbox -ResultSize Unlimited -PropertySets Minimum -ErrorAction Stop |
            Where-Object {
                # Older EXO responses and test doubles might omit the property.
                # Include those objects, but explicitly exclude known system-only
                # mailbox types whenever Exchange provides RecipientTypeDetails.
                -not $_.PSObject.Properties['RecipientTypeDetails'] -or
                [string]::IsNullOrWhiteSpace([string]$_.RecipientTypeDetails) -or
                [string]$_.RecipientTypeDetails -in $supportedTypes
            } |
            Where-Object { $_.PrimarySmtpAddress } |
            ForEach-Object { [string]$_.PrimarySmtpAddress }
    )
}
