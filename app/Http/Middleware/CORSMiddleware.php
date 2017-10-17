<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Response;

class CORSMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure                 $next
     *
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $response = $next($request);

        if ($this->isPreflightRequest($request)
            && $this->canBeConvertedToPreflightResponse($response)) {
            $response = $this->createEmptyResponse();
        }

        return $this->addCorsHeaders($request, $response);
    }

    /**
     * Determine if request is a preflight request.
     *
     * @param \Illiminate\Http\Request $request
     *
     * @return bool
     */
    protected function isPreflightRequest($request)
    {
        return $request->isMethod('OPTIONS');
    }

    /**
     * Determine if response is not an error.
     *
     * @param \Illiminate\Http\Response $response
     *
     * @return bool
     */
    protected function canBeConvertedToPreflightResponse($response)
    {
        return ($response->isSuccessful() || $response->isClientError())
            && !$response->isNotFound();
    }

    /**
     * Create empty response for preflight request.
     *
     * @return \Illiminate\Http\Response
     */
    protected function createEmptyResponse()
    {
        return new Response(null, 204);
    }

    /**
     * Add CORS headers.
     *
     * @param \Illiminate\Http\Request  $request
     * @param \Illiminate\Http\Response $response
     */
    protected function addCorsHeaders($request, $response)
    {
        foreach ([
            'Access-Control-Allow-Origin' => '*',
            'Access-Control-Max-Age' => (60 * 60 * 24),
            'Access-Control-Allow-Headers' => $request->header('Access-Control-Request-Headers'),
            'Access-Control-Allow-Methods' => $request->header('Access-Control-Request-Methods')
                ?: 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS',
            'Access-Control-Allow-Credentials' => 'true',
        ] as $header => $value) {
            $response->header($header, $value);
        }

        return $response;
    }
}
