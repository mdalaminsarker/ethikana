<?php

namespace App\Http\Controllers\Auth;

use JWTAuth;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use App\Http\Controllers\Controller;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Http\Exception\HttpResponseException;

class AuthController extends Controller
{
    /**
     * Handle a login request to the application.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return \Illuminate\Http\Response
     */
    public function postLogin(Request $request)
    {
        try {
            $this->validate($request, [
                'email' => 'required|email|max:255',
                'password' => 'required',
            ]);
        } catch (HttpResponseException $e) {
            return new JsonResponse([
                'error' => [
                    'message' => 'invalid_auth',
                    'status_code' => Response::HTTP_BAD_REQUEST,
                ],
            ], Response::HTTP_BAD_REQUEST);
        }

        $credentials = $this->getCredentials($request);

        try {
            // Attempt to verify the credentials and create a token for the user
            if (!$token = JWTAuth::attempt($credentials)) {
                return new JsonResponse([
                    'error' => [
                        'message' => 'invalid_credentials',
                    ],
                ], Response::HTTP_UNAUTHORIZED);
            }
        } catch (JWTException $e) {
            // Something went wrong whilst attempting to encode the token
            return new JsonResponse([
                'error' => [
                    'message' => 'could_not_create_token',
                ],
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        // All good so return the token
        return new JsonResponse([
            'success' => [
                'message' => 'token_generated',
                'token' => $token,
            ]
        ]);
    }

    /**
     * Get the needed authorization credentials from the request.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return array
     */
    protected function getCredentials(Request $request)
    {
        return $request->only('email', 'password');
    }

    /**
     * Invalidate a token.
     *
     * @return \Illuminate\Http\Response
     */
    public function deleteInvalidate()
    {
        $token = JWTAuth::parseToken();

        $token->invalidate();

        return new JsonResponse(['message' => 'token_invalidated']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\Response
     */
    public function patchRefresh()
    {
        $token = JWTAuth::parseToken();

        $newToken = $token->refresh();

        return new JsonResponse([
            'message' => 'token_refreshed',
            'token' => $newToken
        ]);
    }

    /**
     * Get authenticated user.
     *
     * @return \Illuminate\Http\Response
     */
    public function getUser()
    {
        return new JsonResponse([
            'success' => [
                'user' => JWTAuth::parseToken()->authenticate()
            ]
        ]);
    }
}
