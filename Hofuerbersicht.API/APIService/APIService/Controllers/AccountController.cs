using APIService.DataAccess;
using APIService.Resource;
using APIService.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;

namespace APIService.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class AccountController
    {
        private readonly ITokenService _tokenService;
        private readonly UsersDB _usersDb;
        private readonly IConfiguration _config;

        public AccountController(UsersDB usersDB, ITokenService tokenService, IConfiguration config)
        {
            _tokenService = tokenService;
            _usersDb = usersDB;
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Users users)
        {
            var user = _usersDb.Users.SingleOrDefault(u => u.username == users.username);
            var password = Encode(users.password);
            if (user == null || user.password != password) return null;

            var userClaims = new[]
            {
                new Claim(ClaimTypes.Name, user.username),
                new Claim(ClaimTypes.NameIdentifier, user.id.ToString())
            };

            var jwtToken = _tokenService.GenerateAccessToken(userClaims);
            var refrehToken = _tokenService.GenerateRefreshToken();

            user.refreshToken = refrehToken;
            user.lastLogon = DateTime.Now;
            await _usersDb.SaveChangesAsync();

            return new ObjectResult(new
            {
                token = jwtToken,
                refrehToken = refrehToken
            });
        }

        public static string Encode(string original)
        {
            byte[] encodedBytes;

            using (var md5 = new MD5CryptoServiceProvider())
            {
                var originalBytes = Encoding.Unicode.GetBytes(original);
                encodedBytes = md5.ComputeHash(originalBytes);
            }

            return Convert.ToBase64String(encodedBytes);
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] TokenResource tokenResource)
        {
            var principal = _tokenService.GetPrincipalFromExpiredToken(tokenResource.Token);
            var username = principal.Identity.Name;

            var user = _usersDb.Users.SingleOrDefault(u => u.username == username);
            if (user == null || user.refreshToken != tokenResource.RefreshToken) return new ObjectResult("RefreshToken ist falsch");

            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.refreshToken = newRefreshToken;
            await _usersDb.SaveChangesAsync();

            // var newJwtToken = _tokenService.generateAccessToken(principal.Claims);
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var _refresh_token = Guid.NewGuid().ToString().Replace("-", "");

            var SecurityToken = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Issuer"],
            claims: principal.Claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddMinutes(2),
            signingCredentials: creds);

            return new ObjectResult(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(SecurityToken),
                notBefore = SecurityToken.ValidFrom,
                token_expiration = SecurityToken.ValidTo,
                refresh_token = newRefreshToken,
                IssuedUtc = DateTime.UtcNow,
                refresh_token_expire = DateTime.UtcNow.AddDays(20)
            });

        }
    }
}
