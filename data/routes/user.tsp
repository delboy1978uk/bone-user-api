import "@typespec/http";
import "@typespec/rest";
import "@typespec/openapi3";

using TypeSpec.Http;
using TypeSpec.Rest;

namespace Application;

@tag("User")
@route("/user")
interface UserOps {
  @route("/register")
  @useAuth(NoAuth)
  @doc("Register a new unactivated user onto the system")
  @post op register(@body body: Email): CreatedApiResponse;

  @route("/resend-activation-email")
  @useAuth(NoAuth)
  @doc("Resend the user activation email.")
  @post op resendActivationMail(@body body: Email): CreatedApiResponse;

  @route("/validate-email-token")
  @useAuth(NoAuth)
  @doc("Validate the token from the user's activation email.")
  @post op validateEmailToken(@body body: ActivateAccount): OkApiResponse;

  @route("/activate")
  @useAuth(NoAuth)
  @doc("Activate the user account.")
  @post op activate(@body body: ActivateAccount): SuccessResponse<TokenResponse>;

  @route("/profile")
  @doc("User profile details")
  @get op getProfile(): ReadResponse<User>;

  @route("/profile")
  @doc("Edit user profile details")
  @put op updateProfile(@body body: Person): UpdatedReturn<Person>;

  @route("/image")
  @doc("Upload the user's profile pic")
  @post op upload(
    @header contentType: "multipart/form-data",
    @multipartBody body: {
        avatar: HttpPart<File>
    }): CreatedResponse<File>;

  @route("/image")
  @doc("Download the user's profile pic")
  @get op serveImage(): FileResponse;

  @route("/background-image")
  @doc("Download the user's profile pic")
  @get op serveBackgroundImage(): FileResponse;

  @route("/background-image")
  @doc("Upload the user's profile pic")
  @post op uploadBackgroundImage(
    @header contentType: "multipart/form-data",
    @multipartBody body: {
        background: HttpPart<File>
    }): CreatedResponse<File>;
}
