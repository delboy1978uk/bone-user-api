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
  @doc("Register a new unactivated user onto the system")
  @post
  op register(@body body: Email): CreatedApiResponse;

  @route("/validate-email-token ")
  @doc("Validate the token from the user's activation email.")
  @post
    op validateEmailToken(@body body: ActivateAccount): OkApiResponse;

  @route("/resend-activation-email")
  @doc("Resend the user activation email.")
  @post
    op resendActivationMail(@body body: Email): CreatedApiResponse;

  @route("/activate")
    @doc("Activate the user account.")
    @post
      op activate(@body body: ActivateAccount): SuccessResponse<TokenResponse>;

  @route("/image")
    @doc("Upload the user's profile pic")
    @post
      op upload(@body body: {
        todo: string,
      }): OkApiResponse;
    @doc("Download the user's profile pic")
    @get
      op serveImage(): OkApiResponse;
}
