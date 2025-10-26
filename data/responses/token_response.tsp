model TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: int32;
    refresh_token?: string;
    scope?: string;
}
