using NUnit.Framework;
using System.IdentityModel.Tokens.Jwt;

public class TokenServiceTests
{
    [Test]
    public void GenerateTokenWithClaim_IncludesRoleClaim()
    {
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new System.Collections.Generic.Dictionary<string, string?> {
                { "JwtSettings:Secret", "test-secret-000000000000000000000000" },
                { "JwtSettings:Issuer", "test-issuer" },
                { "JwtSettings:Audience", "test-audience" }
            }).Build();

        var service = new TokenService(config);

        var tokenString = service.GenerateTokenWithClaim("123");

        Assert.IsNotNull(tokenString);

        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);

        var roleClaim = token.Claims.FirstOrDefault(c => c.Type == "Role");
        Assert.IsNotNull(roleClaim, "Token should include a Role claim.");
        Assert.AreEqual("Admin", roleClaim.Value);

        var stdRole = token.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Role);
        Assert.IsNotNull(stdRole, "Token should include ClaimTypes.Role for compatibility.");
        Assert.AreEqual("Admin", stdRole.Value);
    }
}
