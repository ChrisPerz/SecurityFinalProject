// Tests/TestInputValidation.cs
using NUnit.Framework;

[TestFixture]
public class TestInputValidation
{
    // --- SQL Injection Tests ---
    [Test]
    public void TestForSQLInjection_DropTable_ShouldFailValidation()
    {
        string maliciousInput = "DROP TABLE Users;";

        bool result = UserController.IsValidInput(maliciousInput, "username");

        Assert.IsFalse(result, "SQL Injection attempt should not be valid.");
    }

    [Test]
    public void TestForSQLInjection_SelectAll_ShouldFailValidation()
    {
        string maliciousInput = "SELECT * FROM Users";

        bool result = UserController.IsValidInput(maliciousInput, "username");

        Assert.IsFalse(result, "SQL Injection attempt should not be valid.");
    }

    // --- XSS Tests ---
    [Test]
    public void TestForXSS_ScriptTag_ShouldFailValidation()
    {
        string maliciousInput = "<script>alert('XSS');</script>";

        bool result = UserController.IsValidInput(maliciousInput, "username");

        Assert.IsFalse(result, "XSS attempt should not be valid.");
    }

    [Test]
    public void TestForXSS_Sanitize_ShouldEscapeTags()
    {
        string maliciousInput = "<script>alert('XSS');</script>";

        string sanitized = UserController.SanitizeForXss(maliciousInput);

        Assert.IsFalse(sanitized.Contains("<script>"), "Sanitized output should not contain raw <script> tags.");
        Assert.IsTrue(sanitized.Contains("&lt;script&gt;"), "Sanitized output should escape script tags.");
    }

    // --- Valid Input Tests ---
    [Test]
    public void TestValidUsername_ShouldPassValidation()
    {
        string validInput = "Cristian_123";

        bool result = UserController.IsValidInput(validInput, "username");

        Assert.IsTrue(result, "Valid username should pass validation.");
    }

    [Test]
    public void TestValidEmail_ShouldPassValidation()
    {
        string validInput = "test@example.com";

        bool result = UserController.IsValidInput(validInput, "email");

        Assert.IsTrue(result, "Valid email should pass validation.");
    }
}