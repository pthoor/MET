function Test-METIsBuiltInQuarantinePolicyName {
    [CmdletBinding()]
    param([AllowEmptyString()] [string] $Name)

    return $Name -in @(
        'AdminOnlyAccessPolicy'
        'DefaultFullAccessPolicy'
        'DefaultFullAccessWithNotificationPolicy'
        'NotificationEnabledPolicy'
    )
}
