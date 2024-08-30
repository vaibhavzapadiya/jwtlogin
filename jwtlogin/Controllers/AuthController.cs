using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Dapper;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using BCrypt.Net;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using System.Data;

namespace jwtlogin.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly string _connectionString;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IConfiguration configuration, ILogger<AuthController> logger)
        {
            _configuration = configuration;
            _connectionString = _configuration.GetConnectionString("DefaultConnection");
            _logger = logger;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest("Username and password are required.");
            }

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    var user = await connection.QuerySingleOrDefaultAsync<User>(
                        "SELECT * FROM Users WHERE Username = @Username",
                        new { Username = request.Username });

                    if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                    {
                        return Unauthorized("Invalid username or password.");
                    }

                    // Generate JWT token
                    var token = GenerateJwtToken(user);

                    return Ok(new { Token = token });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during login.");
                StatusCode(500, "An unexpected error occurred. Please try again later.");
            }
            return StatusCode(500, "Unexpected issue.");
        }

        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email)
            }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }



        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password) || string.IsNullOrEmpty(request.Email))
            {
                return BadRequest("All fields are required.");
            }

            try
            {
                using (var connection = new SqlConnection(_connectionString))
                {
                    // Check if the username already exists
                    var existingUser = await connection.QuerySingleOrDefaultAsync<User>(
                        "SELECT * FROM Users WHERE Username = @Username",
                        new { Username = request.Username });

                    if (existingUser != null)
                    {
                        return Conflict("Username already exists.");
                    }

                    // Hash the password
                    string hashedPassword = BCrypt.Net.BCrypt.HashPassword(request.Password);

                    // Insert new user into the database
                    var newUser = new User
                    {
                        Username = request.Username,
                        PasswordHash = hashedPassword,
                        Email = request.Email,
                        CreatedAt = DateTime.UtcNow,
                        UpdatedAt = DateTime.UtcNow
                    };

                    var insertQuery = "INSERT INTO Users (Username, PasswordHash, Email, CreatedAt, UpdatedAt) VALUES (@Username, @PasswordHash, @Email, @CreatedAt, @UpdatedAt)";
                    await connection.ExecuteAsync(insertQuery, newUser);

                    return Ok("User registered successfully.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during registration.");
                return StatusCode(500, "Internal server error. Please try again later.");
            }
        }
    }

    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string PasswordHash { get; set; }
        public string Email { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }

    public class RegisterRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
    }
}
