using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;

namespace Identity_Management.Models
{
    /// <summary>
    /// Helper class to convert the claim object into claim identity
    /// </summary>
    public class UserHelper
    {
        /// <summary>
        /// convert claim object into claim identity
        /// </summary>
        /// <param name="user"> current user</param>
        /// <returns> ClaimPrincipal </returns>
        public static ClaimsPrincipal Convert(User user)
        {
            var claims = new List<Claim>()
            {
                new Claim(type: "username", value: user.Username)
            };

            // select is equivalent to where or map
            claims.AddRange(user.Claims.Select(x => new Claim(x.Type, x.Value)));

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            return new ClaimsPrincipal(identity);
        }
    }
}
