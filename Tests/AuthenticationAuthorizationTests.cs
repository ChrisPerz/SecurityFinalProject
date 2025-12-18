using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using SecurityFinalProject.Models;
using System.Threading.Tasks;

[TestFixture]
public class AuthenticationAuthorizationTests
{
    class FakeDbService : DatabaseService
    {
        private readonly UserModel? _userToReturn;

        public FakeDbService(UserModel? userToReturn)
        {
            _userToReturn = userToReturn;
        }

        public override Task<UserModel?> GetUserByEmailAsync(string email)
        {
            return Task.FromResult(_userToReturn);
        }

        // Keep CreateUser behavior as-is if needed in future tests
    }

    [Test]
    public async Task Login_MissingEmailOrPassword_ReturnsBadRequest()
    {
        var db = new FakeDbService(null);
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection().Build();
        var tokenService = new TokenService(config);
        var passwordService = new PasswordService();
        var controller = new UserController(db, tokenService, passwordService);

        var result = await controller.Login("", "");

        Assert.IsInstanceOf<BadRequestObjectResult>(result);
    }

    [Test]
    public async Task Login_InvalidEmail_ReturnsUnauthorized()
    {
        var db = new FakeDbService(null);
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection().Build();
        var tokenService = new TokenService(config);
        var passwordService = new PasswordService();
        var controller = new UserController(db, tokenService, passwordService);

        var result = await controller.Login("notfound@example.com", "irrelevant");

        Assert.IsInstanceOf<UnauthorizedObjectResult>(result);
    }

    [Test]
    public async Task Login_InvalidPassword_ReturnsUnauthorized()
    {
        var passwordService = new PasswordService();
        var hashed = passwordService.HashPassword("correct_password");
        var user = new UserModel { UserId = 1, Email = "u@example.com", Username = "u", HashedPassword = hashed };
        var db = new FakeDbService(user);
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection().Build();
        var tokenService = new TokenService(config);
        var controller = new UserController(db, tokenService, passwordService);

        var result = await controller.Login("u@example.com", "wrong_password");

        Assert.IsInstanceOf<UnauthorizedObjectResult>(result);
    }

    [Test]
    public async Task Login_ValidCredentials_ReturnsOkWithToken()
    {
        var passwordService = new PasswordService();
        var hashed = passwordService.HashPassword("secret123");
        var user = new UserModel { UserId = 99, Email = "valid@example.com", Username = "validuser", HashedPassword = hashed };
        var db = new FakeDbService(user);

        // Provide minimal Jwt settings so TokenService can be constructed.
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new System.Collections.Generic.Dictionary<string, string>
            {
                { "JwtSettings:Secret", "super-secret-key-1234567890123456" },
                { "JwtSettings:Issuer", "test-issuer" },
                { "JwtSettings:Audience", "test-audience" }
            }).Build();

        var tokenService = new TokenService(config);
        var controller = new UserController(db, tokenService, passwordService);

        var result = await controller.Login("valid@example.com", "secret123");

        Assert.IsInstanceOf<OkObjectResult>(result);
        var ok = result as OkObjectResult;
        Assert.IsNotNull(ok?.Value);
        // Expect an anonymous object with a Token property
        var tokenProp = ok.Value.GetType().GetProperty("Token");
        Assert.IsNotNull(tokenProp, "Expected a Token property in response payload.");
        var token = tokenProp.GetValue(ok.Value) as string;
        Assert.IsFalse(string.IsNullOrWhiteSpace(token));
    }

    [Test]
    public async Task AdminPolicy_AllowsOnlyCorrectClaim()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthorization(options =>
        {
            options.AddPolicy("AdminOnly", policy => policy.RequireClaim("Role", "Admin"));
        });

        var provider = services.BuildServiceProvider();
        var authz = provider.GetRequiredService<IAuthorizationService>();

        var userWithAdminRole = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("Role", "Admin") }, "TestAuth"));
        var resultOk = await authz.AuthorizeAsync(userWithAdminRole, null, "AdminOnly");
        Assert.IsTrue(resultOk.Succeeded, "Principal with Role=Admin should satisfy the policy.");

        var userWithLowercaseRole = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("role", "admin") }, "TestAuth"));
        var resultFail = await authz.AuthorizeAsync(userWithLowercaseRole, null, "AdminOnly");
        Assert.IsFalse(resultFail.Succeeded, "Principal with lowercase claim names/values should not satisfy the policy as configured.");

        var userWithoutRole = new ClaimsPrincipal(new ClaimsIdentity());
        var resultFail2 = await authz.AuthorizeAsync(userWithoutRole, null, "AdminOnly");
        Assert.IsFalse(resultFail2.Succeeded, "Principal without Role claim should not satisfy the policy.");
    }
}
