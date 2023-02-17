rule phishing_email
{
    meta:
        description = "Detects phishing emails"
        author = "Your Name"

    strings:
        $subject = "Urgent: Update your account information"
        $body = "Dear Customer, 

        We are writing to inform you that your account needs to be updated. Please click on the link below to verify your account information. 

        Sincerely,
        Your Bank"

    condition:
        $subject or $body
}
