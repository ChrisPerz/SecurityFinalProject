using NUnit.Framework;
using SecurityFinalProject.Models;
using System;
using System.Threading.Tasks;

public class UserControllerTests
{
    class CapturingDbService : DatabaseService
    {
        public string? CapturedUsername;
        public string? CapturedEmail;
        public string? CapturedPassword;

        public override void CreateUser(string username, string email, string password)
        {
            CapturedUsername = username;
            CapturedEmail = email;
            CapturedPassword = password;
            // do not call base (no-db in tests)
        }
    }

    [Test]
    public void Create_StoresHashedPassword_NotPlaintext()
    {
        var db = new CapturingDbService();
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection().Build();
        var tokenService = new TokenService(config);
        var passwordService = new PasswordService();
        var controller = new UserController(db, tokenService, passwordService);

        var model = new UserModel { Username = "validUser", Email = "test@example.com", Password = "secret123" };

        var result = controller.Create(model);

        // Ensure database received a password, and it's not the plaintext password
        Assert.IsNotNull(db.CapturedPassword, "CreateUser should be called and a password saved.");
        Assert.AreNotEqual("secret123", db.CapturedPassword, "Stored password should not be the plaintext password.");

        // Stored password should verify against the original
        Assert.IsTrue(passwordService.VerifyPassword("secret123", db.CapturedPassword), "The stored hash should verify the original password.");
    }

    [Test]
    public void Create_InvalidUsername_AddsModelError()
    {
        var db = new CapturingDbService();
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection().Build();
        var tokenService = new TokenService(config);
        var passwordService = new PasswordService();
        var controller = new UserController(db, tokenService, passwordService);

        var model = new UserModel { Username = "<script>alert(1)</script>", Email = "test@example.com", Password = "secret123" };

        var result = controller.Create(model);

        Assert.IsFalse(controller.ModelState.IsValid, "ModelState should be invalid due to unsafe username.");
        Assert.IsTrue(controller.ModelState[string.Empty].Errors.Count > 0, "An input validation error should be present.");
    }
}
