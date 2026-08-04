using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityPortal.Application.Features.Auth.Commands;
using SecurityPortal.Application.Features.Auth.DTOs;

namespace SecurityPortal.API.Controllers.v1;

public class AuthController(IMediator mediator) : BaseController(mediator)
{
    /// <summary>Authenticate with email and password</summary>
    [AllowAnonymous]
    [HttpPost("login")]
    [ProducesResponseType(typeof(AuthResponse), 200)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var userAgent = Request.Headers.UserAgent.ToString();
        var command = new LoginCommand(request.Email, request.Password, ipAddress, userAgent);
        var result = await Mediator.Send(command);
        return Ok(result);
    }

    /// <summary>Register a new account and organization</summary>
    [AllowAnonymous]
    [HttpPost("register")]
    [ProducesResponseType(typeof(AuthResponse), 201)]
    [ProducesResponseType(422)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var command = new RegisterCommand(
            request.Email, request.Username, request.Password,
            request.FirstName, request.LastName, request.OrganizationName);

        var result = await Mediator.Send(command);
        return StatusCode(201, result);
    }

    /// <summary>Refresh the access token using a valid refresh token</summary>
    [AllowAnonymous]
    [HttpPost("refresh")]
    [ProducesResponseType(typeof(AuthResponse), 200)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
    {
        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var command = new RefreshTokenCommand(request.RefreshToken, ipAddress);
        var result = await Mediator.Send(command);
        return Ok(result);
    }

    /// <summary>Revoke a refresh token (logout)</summary>
    [AllowAnonymous]
    [HttpPost("revoke")]
    [ProducesResponseType(204)]
    public async Task<IActionResult> Revoke([FromBody] RefreshTokenRequest request)
    {
        await Mediator.Send(new RevokeTokenCommand(request.RefreshToken));
        return NoContent();
    }

    /// <summary>Change password for the authenticated user</summary>
    [HttpPost("change-password")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        await Mediator.Send(new ChangePasswordCommand(CurrentUserId, request.CurrentPassword, request.NewPassword));
        return NoContent();
    }

    /// <summary>Update profile for the authenticated user</summary>
    [HttpPut("profile")]
    [ProducesResponseType(typeof(UserDto), 200)]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request)
    {
        var result = await Mediator.Send(
            new UpdateProfileCommand(CurrentUserId, request.FirstName, request.LastName, request.AvatarUrl));
        return Ok(result);
    }
}
