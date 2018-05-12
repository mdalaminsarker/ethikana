<?php
namespace App\Http\Middleware;
use Closure;

use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
//use Symfony\Component\HttpFoundation\Response ;
class ThrottleRequests
{
    /**
     * The rate limiter instance.
     *
     * @var \Illuminate\Cache\RateLimiter
     */
    protected $limiter;
    /**
     * Create a new request throttler.
     *
     * @param  \Illuminate\Cache\RateLimiter  $limiter
     * @return void
     */
    public function __construct(RateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  int  $maxAttempts
     * @param  int  $decayMinutes
     * @return mixed
     */
    public function handle($request, Closure $next, $maxAttempts = 60, $decayMinutes = 1)
    {
        $key = $this->resolveRequestSignature($request);
        if ($this->limiter->tooManyAttempts($key, $maxAttempts, $decayMinutes)) {
            return $this->buildResponse($key, $maxAttempts);
        }
        $this->limiter->hit($key, $decayMinutes);
        $response = $next($request);

        return $this->addHeaders(
            $response, $maxAttempts,
            $this->calculateRemainingAttempts($key, $maxAttempts)
        );
    }
    /**
     * Resolve request signature.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
     protected function resolveRequestSignature($request)
     {
     return sha1(
         $request->method() .
         '|' . $request->server('SERVER_NAME') .
         '|' . $request->path() .
         '|' . $request->ip()
     );
    }
    /**
     * Create a 'too many attempts' response.
     *
     * @param  string  $key
     * @param  int  $maxAttempts
     * @return \Illuminate\Http\Response
     */
    protected function buildResponse($key, $maxAttempts)
    {
        $retryAfter = $this->limiter->availableIn($key);
        $response = new JsonResponse([
          'Retry After' => $retryAfter,
          'Message ' => 'Too Many Attempts',
          'Status'=> 429]);

        return $this->addHeaders(
            $response, $maxAttempts,
            $this->calculateRemainingAttempts($key, $maxAttempts, $retryAfter),
            $retryAfter
        );
    }
    /**
     * Add the limit header information to the given response.
     *
     * @param  \Symfony\Component\HttpFoundation\Response  $response
     * @param  int  $maxAttempts
     * @param  int  $remainingAttempts
     * @param  int|null  $retryAfter
     * @return \Illuminate\Http\Response
     */
    protected function addHeaders(JsonResponse $response, $maxAttempts, $remainingAttempts, $retryAfter = null)
    {
        $headers = [
            'X-RateLimit-Limit' => $maxAttempts,
            'X-RateLimit-Remaining' => $remainingAttempts,
            'Retry-After' => $retryAfter,
        ];
        if (! is_null($retryAfter)) {
            $headers['Retry-After'] = $retryAfter;
        }
        $response->headers->add($headers);
        return $response;
    }
    /**
     * Calculate the number of remaining attempts.
     *
     * @param  string  $key
     * @param  int  $maxAttempts
     * @param  int|null  $retryAfter
     * @return int
     */
    protected function calculateRemainingAttempts($key, $maxAttempts, $retryAfter = null)
    {
        if (! is_null($retryAfter)) {
            return 0;
        }
        return $this->limiter->retriesLeft($key, $maxAttempts);
    }
}
