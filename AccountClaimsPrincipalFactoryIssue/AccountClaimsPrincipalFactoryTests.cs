using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication.Internal;
using Moq;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace AccountClaimsPrincipalFactoryIssue
{
    public class AccountClaimsPrincipalFactoryTests
    {
        [Fact]
        public async Task CreateUserAsync_WithSingleRole_CreatesOneRoleClaim()
        {
            var mock = new Mock<IAccessTokenProviderAccessor>();

            var factory = new AccountClaimsPrincipalFactory<RemoteUserAccount>(mock.Object);

            var jsonAccount = "{\"exp\":1594647980,\"nbf\":1594644380,\"ver\":\"1.0\",\"iss\":\"https://blazorb2c.b2clogin.com/f9c7fda4-83aa-4664-b51b-23f1961de920/v2.0/\",\"sub\":\"73a93788-a470-454f-bc38-23abfc42a514\",\"aud\":\"66e7a1e8-a1e6-4394-8aef-3163c4a9d4b7\",\"nonce\":\"e9588167-2d1d-46c0-9a19-d63f30059ff4\",\"iat\":1594644380,\"auth_time\":1594644380,\"oid\":\"73a93788-a470-454f-bc38-23abfc42a514\",\"name\":\"Marco Des\",\"tfp\":\"B2C_1_signupin\", \"role\":\"user\"}";

            var account = JsonSerializer.Deserialize<RemoteUserAccount>(jsonAccount);

            var options = new RemoteAuthenticationUserOptions()
            {
                NameClaim = "name",
                RoleClaim = "role"
            };

            var principal = await factory.CreateUserAsync(account, options);

            var roles = principal.FindAll("role").ToList();

            Assert.Single(roles);
            Assert.Equal("user", roles[0].Value);
        }

        [Fact]
        public async Task CreateUserAsync_WithMultipleRoles_CreatesOneRoleClaimPerValue()
        {
            var mock = new Mock<IAccessTokenProviderAccessor>();

            var factory = new AccountClaimsPrincipalFactory<RemoteUserAccount>(mock.Object);

            var jsonAccount = "{\"exp\":1594647980,\"nbf\":1594644380,\"ver\":\"1.0\",\"iss\":\"https://blazorb2c.b2clogin.com/f9c7fda4-83aa-4664-b51b-23f1961de920/v2.0/\",\"sub\":\"73a93788-a470-454f-bc38-23abfc42a514\",\"aud\":\"66e7a1e8-a1e6-4394-8aef-3163c4a9d4b7\",\"nonce\":\"e9588167-2d1d-46c0-9a19-d63f30059ff4\",\"iat\":1594644380,\"auth_time\":1594644380,\"oid\":\"73a93788-a470-454f-bc38-23abfc42a514\",\"name\":\"Marco Des\",\"tfp\":\"B2C_1_signupin\", \"role\": [ \"user\", \"superUser\" ]}";

            var account = JsonSerializer.Deserialize<RemoteUserAccount>(jsonAccount);

            var options = new RemoteAuthenticationUserOptions()
            {
                NameClaim = "name",
                RoleClaim = "role"
            };

            var principal = await factory.CreateUserAsync(account, options);

            var roles = principal.FindAll("role").ToList();

            // this assertion fails because instead of 2 roles claim, there is
            // only 1 role claim whose value is the JSON serialization of the array:
            // [ "user", "superUser" ]
            // this is not how claims are supposed to work in the ClaimsIdentity object
            Assert.Equal(2, roles.Count);
            Assert.Equal("user", roles[0].Value);
            Assert.Equal("superUser", roles[1].Value);
        }
    }
}
