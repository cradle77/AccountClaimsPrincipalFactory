using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication.Internal;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;

namespace AccountClaimsPrincipalFactoryIssue
{
    public class ArrayClaimsPrincipalFactory<TAccount> : AccountClaimsPrincipalFactory<TAccount> where TAccount : RemoteUserAccount
    {
        public ArrayClaimsPrincipalFactory(IAccessTokenProviderAccessor accessor)
        : base(accessor)
        { }


        // when a user belongs to multiple roles, IS4 returns a single claim with a serialised array of values
        // this class improves the original factory by deserializing the claims in the correct way
        public override ValueTask<ClaimsPrincipal> CreateUserAsync(TAccount account, RemoteAuthenticationUserOptions options)
        {
            var identity = account != null ? new ClaimsIdentity(
            options.AuthenticationType,
            options.NameClaim,
            options.RoleClaim) : new ClaimsIdentity();

            if (account != null)
            {
                foreach (var kvp in account.AdditionalProperties)
                {
                    var name = kvp.Key;
                    var value = kvp.Value;
                    if (value != null ||
                        (value is JsonElement element && element.ValueKind != JsonValueKind.Undefined && element.ValueKind != JsonValueKind.Null))
                    {
                        element = (JsonElement)value;

                        if (element.ValueKind == JsonValueKind.Array)
                        {
                            var claims = element.EnumerateArray()
                            .Select(x => new Claim(kvp.Key, x.ToString()));

                            identity.AddClaims(claims);
                        }
                        else
                        {
                            identity.AddClaim(new Claim(name, value.ToString()));
                        }
                    }
                }
            }

            return new ValueTask<ClaimsPrincipal>(new ClaimsPrincipal(identity));
        }
    }
}
