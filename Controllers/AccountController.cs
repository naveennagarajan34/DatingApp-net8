using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController(DataContext context, ITokenService tokenService) : BaseApiController
{
    [HttpPost("register")]          // Endpoint:  /account/register
    public async Task<ActionResult<UserDto>> Register (RegisterDto registerDto) {
        
        if(await UserExists(registerDto.Username)) return BadRequest("Username already exists");

        return Ok();

        // using var hmac = new HMACSHA512();
        
        // var user = new AppUser 
        // {
        //     UserName = registerDto.Username.ToLower(),
        //     PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
        //     PasswordSalt = hmac.Key
        // };
        // context.Users.Add(user);                // Add the registered user to the database
        // await context.SaveChangesAsync();       // save the user registered in the database
        // return new UserDto
        // {
        //    Username = user.UserName,
        //    Token =  tokenService.CreateToken(user)
        // };
    }
    
    [HttpPost("login")]            // Endpoint: /account/login
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto) {
        var user = await context.Users.FirstOrDefaultAsync(x => x.UserName.ToLower() == loginDto.Username.ToLower());
        
        if(user == null) return Unauthorized("Invalid username");

        using var hmac = new HMACSHA512(user.PasswordSalt);
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

        for (int i = 0; i < computedHash.Length; i++)
        {
            if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
        }
        return new UserDto
        {
            Username = user.UserName,
            Token =  tokenService.CreateToken(user)
        };
    } 

    private async Task<bool> UserExists(string username) 
    {
        return await context.Users.AnyAsync(x => x.UserName.ToLower() == username.ToLower());  // compares the username  
    }
}
