<?php
namespace Illuminate\Contracts\Container {
use Closure;
interface Container
{
    public function bound($abstract);
    public function alias($abstract, $alias);
    public function tag($abstracts, $tags);
    public function tagged($tag);
    public function bind($abstract, $concrete = null, $shared = false);
    public function bindIf($abstract, $concrete = null, $shared = false);
    public function singleton($abstract, $concrete = null);
    public function extend($abstract, Closure $closure);
    public function instance($abstract, $instance);
    public function when($concrete);
    public function make($abstract, array $parameters = []);
    public function call($callback, array $parameters = [], $defaultMethod = null);
    public function resolved($abstract);
    public function resolving($abstract, Closure $callback = null);
    public function afterResolving($abstract, Closure $callback = null);
}
}

namespace Illuminate\Contracts\Container {
interface ContextualBindingBuilder
{
    public function needs($abstract);
    public function give($implementation);
}
}

namespace Illuminate\Contracts\Foundation {
use Illuminate\Contracts\Container\Container;
interface Application extends Container
{
    public function version();
    public function basePath();
    public function environment();
    public function isDownForMaintenance();
    public function registerConfiguredProviders();
    public function register($provider, $options = [], $force = false);
    public function registerDeferredProvider($provider, $service = null);
    public function boot();
    public function booting($callback);
    public function booted($callback);
    public function getCachedCompilePath();
    public function getCachedServicesPath();
}
}

namespace Illuminate\Contracts\Bus {
interface Dispatcher
{
    public function dispatch($command);
    public function dispatchNow($command, $handler = null);
    public function pipeThrough(array $pipes);
}
}

namespace Illuminate\Contracts\Bus {
interface QueueingDispatcher extends Dispatcher
{
    public function dispatchToQueue($command);
}
}

namespace Illuminate\Contracts\Pipeline {
use Closure;
interface Pipeline
{
    public function send($traveler);
    public function through($stops);
    public function via($method);
    public function then(Closure $destination);
}
}

namespace Illuminate\Contracts\Support {
interface Renderable
{
    public function render();
}
}

namespace Illuminate\Contracts\Logging {
interface Log
{
    public function alert($message, array $context = []);
    public function critical($message, array $context = []);
    public function error($message, array $context = []);
    public function warning($message, array $context = []);
    public function notice($message, array $context = []);
    public function info($message, array $context = []);
    public function debug($message, array $context = []);
    public function log($level, $message, array $context = []);
    public function useFiles($path, $level = 'debug');
    public function useDailyFiles($path, $days = 0, $level = 'debug');
}
}

namespace Illuminate\Contracts\Debug {
use Exception;
interface ExceptionHandler
{
    public function report(Exception $e);
    public function render($request, Exception $e);
    public function renderForConsole($output, Exception $e);
}
}

namespace Illuminate\Contracts\Config {
interface Repository
{
    public function has($key);
    public function get($key, $default = null);
    public function all();
    public function set($key, $value = null);
    public function prepend($key, $value);
    public function push($key, $value);
}
}

namespace Illuminate\Contracts\Events {
interface Dispatcher
{
    public function listen($events, $listener, $priority = 0);
    public function hasListeners($eventName);
    public function push($event, $payload = []);
    public function subscribe($subscriber);
    public function until($event, $payload = []);
    public function flush($event);
    public function fire($event, $payload = [], $halt = false);
    public function firing();
    public function forget($event);
    public function forgetPushed();
}
}

namespace Illuminate\Contracts\Support {
interface Arrayable
{
    public function toArray();
}
}

namespace Illuminate\Contracts\Support {
interface Jsonable
{
    public function toJson($options = 0);
}
}

namespace Illuminate\Contracts\Cookie {
interface Factory
{
    public function make($name, $value, $minutes = 0, $path = null, $domain = null, $secure = false, $httpOnly = true);
    public function forever($name, $value, $path = null, $domain = null, $secure = false, $httpOnly = true);
    public function forget($name, $path = null, $domain = null);
}
}

namespace Illuminate\Contracts\Cookie {
interface QueueingFactory extends Factory
{
    public function queue();
    public function unqueue($name);
    public function getQueuedCookies();
}
}

namespace Illuminate\Contracts\Encryption {
interface Encrypter
{
    public function encrypt($value);
    public function decrypt($payload);
}
}

namespace Illuminate\Contracts\Queue {
interface QueueableEntity
{
    public function getQueueableId();
}
}

namespace Illuminate\Contracts\Routing {
use Closure;
interface Registrar
{
    public function get($uri, $action);
    public function post($uri, $action);
    public function put($uri, $action);
    public function delete($uri, $action);
    public function patch($uri, $action);
    public function options($uri, $action);
    public function match($methods, $uri, $action);
    public function resource($name, $controller, array $options = []);
    public function group(array $attributes, Closure $callback);
    public function substituteBindings($route);
    public function substituteImplicitBindings($route);
}
}

namespace Illuminate\Contracts\Routing {
interface ResponseFactory
{
    public function make($content = '', $status = 200, array $headers = []);
    public function view($view, $data = [], $status = 200, array $headers = []);
    public function json($data = [], $status = 200, array $headers = [], $options = 0);
    public function jsonp($callback, $data = [], $status = 200, array $headers = [], $options = 0);
    public function stream($callback, $status = 200, array $headers = []);
    public function download($file, $name = null, array $headers = [], $disposition = 'attachment');
    public function redirectTo($path, $status = 302, $headers = [], $secure = null);
    public function redirectToRoute($route, $parameters = [], $status = 302, $headers = []);
    public function redirectToAction($action, $parameters = [], $status = 302, $headers = []);
    public function redirectGuest($path, $status = 302, $headers = [], $secure = null);
    public function redirectToIntended($default = '/', $status = 302, $headers = [], $secure = null);
}
}

namespace Illuminate\Contracts\Routing {
interface UrlGenerator
{
    public function current();
    public function to($path, $extra = [], $secure = null);
    public function secure($path, $parameters = []);
    public function asset($path, $secure = null);
    public function route($name, $parameters = [], $absolute = true);
    public function action($action, $parameters = [], $absolute = true);
    public function setRootControllerNamespace($rootNamespace);
}
}

namespace Illuminate\Contracts\Routing {
interface UrlRoutable
{
    public function getRouteKey();
    public function getRouteKeyName();
}
}

namespace Illuminate\Contracts\Validation {
interface ValidatesWhenResolved
{
    public function validate();
}
}

namespace Illuminate\Contracts\View {
interface Factory
{
    public function exists($view);
    public function file($path, $data = [], $mergeData = []);
    public function make($view, $data = [], $mergeData = []);
    public function share($key, $value = null);
    public function composer($views, $callback, $priority = null);
    public function creator($views, $callback);
    public function addNamespace($namespace, $hints);
}
}

namespace Illuminate\Contracts\Support {
interface MessageProvider
{
    public function getMessageBag();
}
}

namespace Illuminate\Contracts\Support {
interface MessageBag
{
    public function keys();
    public function add($key, $message);
    public function merge($messages);
    public function has($key);
    public function first($key = null, $format = null);
    public function get($key, $format = null);
    public function all($format = null);
    public function getFormat();
    public function setFormat($format = ':message');
    public function isEmpty();
    public function count();
    public function toArray();
}
}

namespace Illuminate\Contracts\View {
use Illuminate\Contracts\Support\Renderable;
interface View extends Renderable
{
    public function name();
    public function with($key, $value = null);
}
}

namespace Illuminate\Contracts\Http {
interface Kernel
{
    public function bootstrap();
    public function handle($request);
    public function terminate($request, $response);
    public function getApplication();
}
}

namespace Illuminate\Contracts\Auth {
interface Guard
{
    public function check();
    public function guest();
    public function user();
    public function id();
    public function validate(array $credentials = []);
    public function setUser(Authenticatable $user);
}
}

namespace Illuminate\Contracts\Auth {
interface StatefulGuard extends Guard
{
    public function attempt(array $credentials = [], $remember = false, $login = true);
    public function once(array $credentials = []);
    public function login(Authenticatable $user, $remember = false);
    public function loginUsingId($id, $remember = false);
    public function onceUsingId($id);
    public function viaRemember();
    public function logout();
}
}

namespace Illuminate\Contracts\Auth\Access {
interface Gate
{
    public function has($ability);
    public function define($ability, $callback);
    public function policy($class, $policy);
    public function before(callable $callback);
    public function after(callable $callback);
    public function allows($ability, $arguments = []);
    public function denies($ability, $arguments = []);
    public function check($ability, $arguments = []);
    public function authorize($ability, $arguments = []);
    public function getPolicyFor($class);
    public function forUser($user);
}
}

namespace Illuminate\Contracts\Hashing {
interface Hasher
{
    public function make($value, array $options = []);
    public function check($value, $hashedValue, array $options = []);
    public function needsRehash($hashedValue, array $options = []);
}
}

namespace Illuminate\Contracts\Auth {
interface UserProvider
{
    public function retrieveById($identifier);
    public function retrieveByToken($identifier, $token);
    public function updateRememberToken(Authenticatable $user, $token);
    public function retrieveByCredentials(array $credentials);
    public function validateCredentials(Authenticatable $user, array $credentials);
}
}

namespace Illuminate\Contracts\Pagination {
interface Paginator
{
    public function url($page);
    public function appends($key, $value = null);
    public function fragment($fragment = null);
    public function nextPageUrl();
    public function previousPageUrl();
    public function items();
    public function firstItem();
    public function lastItem();
    public function perPage();
    public function currentPage();
    public function hasPages();
    public function hasMorePages();
    public function isEmpty();
    public function render($view = null);
}
}

namespace Illuminate\Auth {
use Closure;
use InvalidArgumentException;
use Illuminate\Contracts\Auth\Factory as FactoryContract;
class AuthManager implements FactoryContract
{
    use CreatesUserProviders;
    protected $app;
    protected $customCreators = [];
    protected $guards = [];
    protected $userResolver;
    public function __construct($app)
    {
        $this->app = $app;
        $this->userResolver = function ($guard = null) {
            return $this->guard($guard)->user();
        };
    }
    public function guard($name = null)
    {
        $name = $name ?: $this->getDefaultDriver();
        return isset($this->guards[$name]) ? $this->guards[$name] : ($this->guards[$name] = $this->resolve($name));
    }
    protected function resolve($name)
    {
        $config = $this->getConfig($name);
        if (is_null($config)) {
            throw new InvalidArgumentException("Auth guard [{$name}] is not defined.");
        }
        if (isset($this->customCreators[$config['driver']])) {
            return $this->callCustomCreator($name, $config);
        }
        $driverMethod = 'create' . ucfirst($config['driver']) . 'Driver';
        if (method_exists($this, $driverMethod)) {
            return $this->{$driverMethod}($name, $config);
        }
        throw new InvalidArgumentException("Auth guard driver [{$name}] is not defined.");
    }
    protected function callCustomCreator($name, array $config)
    {
        return $this->customCreators[$config['driver']]($this->app, $name, $config);
    }
    public function createSessionDriver($name, $config)
    {
        $provider = $this->createUserProvider($config['provider']);
        $guard = new SessionGuard($name, $provider, $this->app['session.store']);
        if (method_exists($guard, 'setCookieJar')) {
            $guard->setCookieJar($this->app['cookie']);
        }
        if (method_exists($guard, 'setDispatcher')) {
            $guard->setDispatcher($this->app['events']);
        }
        if (method_exists($guard, 'setRequest')) {
            $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));
        }
        return $guard;
    }
    public function createTokenDriver($name, $config)
    {
        $guard = new TokenGuard($this->createUserProvider($config['provider']), $this->app['request']);
        $this->app->refresh('request', $guard, 'setRequest');
        return $guard;
    }
    protected function getConfig($name)
    {
        return $this->app['config']["auth.guards.{$name}"];
    }
    public function getDefaultDriver()
    {
        return $this->app['config']['auth.defaults.guard'];
    }
    public function shouldUse($name)
    {
        $name = $name ?: $this->getDefaultDriver();
        $this->setDefaultDriver($name);
        $this->userResolver = function ($name = null) {
            return $this->guard($name)->user();
        };
    }
    public function setDefaultDriver($name)
    {
        $this->app['config']['auth.defaults.guard'] = $name;
    }
    public function viaRequest($driver, callable $callback)
    {
        return $this->extend($driver, function () use($callback) {
            $guard = new RequestGuard($callback, $this->app['request']);
            $this->app->refresh('request', $guard, 'setRequest');
            return $guard;
        });
    }
    public function userResolver()
    {
        return $this->userResolver;
    }
    public function resolveUsersUsing(Closure $userResolver)
    {
        $this->userResolver = $userResolver;
        return $this;
    }
    public function extend($driver, Closure $callback)
    {
        $this->customCreators[$driver] = $callback;
        return $this;
    }
    public function provider($name, Closure $callback)
    {
        $this->customProviderCreators[$name] = $callback;
        return $this;
    }
    public function __call($method, $parameters)
    {
        return $this->guard()->{$method}(...$parameters);
    }
}
}

namespace Illuminate\Auth {
use RuntimeException;
use Illuminate\Support\Str;
use Illuminate\Http\Response;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Auth\StatefulGuard;
use Symfony\Component\HttpFoundation\Request;
use Illuminate\Contracts\Auth\SupportsBasicAuth;
use Illuminate\Contracts\Cookie\QueueingFactory as CookieJar;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
class SessionGuard implements StatefulGuard, SupportsBasicAuth
{
    use GuardHelpers;
    protected $name;
    protected $lastAttempted;
    protected $viaRemember = false;
    protected $session;
    protected $cookie;
    protected $request;
    protected $events;
    protected $loggedOut = false;
    protected $tokenRetrievalAttempted = false;
    public function __construct($name, UserProvider $provider, SessionInterface $session, Request $request = null)
    {
        $this->name = $name;
        $this->session = $session;
        $this->request = $request;
        $this->provider = $provider;
    }
    public function user()
    {
        if ($this->loggedOut) {
            return;
        }
        if (!is_null($this->user)) {
            return $this->user;
        }
        $id = $this->session->get($this->getName());
        $user = null;
        if (!is_null($id)) {
            if ($user = $this->provider->retrieveById($id)) {
                $this->fireAuthenticatedEvent($user);
            }
        }
        $recaller = $this->getRecaller();
        if (is_null($user) && !is_null($recaller)) {
            $user = $this->getUserByRecaller($recaller);
            if ($user) {
                $this->updateSession($user->getAuthIdentifier());
                $this->fireLoginEvent($user, true);
            }
        }
        return $this->user = $user;
    }
    public function id()
    {
        if ($this->loggedOut) {
            return;
        }
        $id = $this->session->get($this->getName());
        if (is_null($id) && $this->user()) {
            $id = $this->user()->getAuthIdentifier();
        }
        return $id;
    }
    protected function getUserByRecaller($recaller)
    {
        if ($this->validRecaller($recaller) && !$this->tokenRetrievalAttempted) {
            $this->tokenRetrievalAttempted = true;
            list($id, $token) = explode('|', $recaller, 2);
            $this->viaRemember = !is_null($user = $this->provider->retrieveByToken($id, $token));
            return $user;
        }
    }
    protected function getRecaller()
    {
        return $this->request->cookies->get($this->getRecallerName());
    }
    protected function getRecallerId()
    {
        if ($this->validRecaller($recaller = $this->getRecaller())) {
            return head(explode('|', $recaller));
        }
    }
    protected function validRecaller($recaller)
    {
        if (!is_string($recaller) || !Str::contains($recaller, '|')) {
            return false;
        }
        $segments = explode('|', $recaller);
        return count($segments) == 2 && trim($segments[0]) !== '' && trim($segments[1]) !== '';
    }
    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);
            return true;
        }
        return false;
    }
    public function validate(array $credentials = [])
    {
        return $this->attempt($credentials, false, false);
    }
    public function basic($field = 'email', $extraConditions = [])
    {
        if ($this->check()) {
            return;
        }
        if ($this->attemptBasic($this->getRequest(), $field, $extraConditions)) {
            return;
        }
        return $this->getBasicResponse();
    }
    public function onceBasic($field = 'email', $extraConditions = [])
    {
        $credentials = $this->getBasicCredentials($this->getRequest(), $field);
        if (!$this->once(array_merge($credentials, $extraConditions))) {
            return $this->getBasicResponse();
        }
    }
    protected function attemptBasic(Request $request, $field, $extraConditions = [])
    {
        if (!$request->getUser()) {
            return false;
        }
        $credentials = $this->getBasicCredentials($request, $field);
        return $this->attempt(array_merge($credentials, $extraConditions));
    }
    protected function getBasicCredentials(Request $request, $field)
    {
        return [$field => $request->getUser(), 'password' => $request->getPassword()];
    }
    protected function getBasicResponse()
    {
        $headers = ['WWW-Authenticate' => 'Basic'];
        return new Response('Invalid credentials.', 401, $headers);
    }
    public function attempt(array $credentials = [], $remember = false, $login = true)
    {
        $this->fireAttemptEvent($credentials, $remember, $login);
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
        if ($this->hasValidCredentials($user, $credentials)) {
            if ($login) {
                $this->login($user, $remember);
            }
            return true;
        }
        if ($login) {
            $this->fireFailedEvent($user, $credentials);
        }
        return false;
    }
    protected function hasValidCredentials($user, $credentials)
    {
        return !is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }
    protected function fireAttemptEvent(array $credentials, $remember, $login)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Attempting($credentials, $remember, $login));
        }
    }
    protected function fireFailedEvent($user, array $credentials)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Failed($user, $credentials));
        }
    }
    public function attempting($callback)
    {
        if (isset($this->events)) {
            $this->events->listen(Events\Attempting::class, $callback);
        }
    }
    public function login(AuthenticatableContract $user, $remember = false)
    {
        $this->updateSession($user->getAuthIdentifier());
        if ($remember) {
            $this->createRememberTokenIfDoesntExist($user);
            $this->queueRecallerCookie($user);
        }
        $this->fireLoginEvent($user, $remember);
        $this->setUser($user);
    }
    protected function fireLoginEvent($user, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Login($user, $remember));
        }
    }
    protected function fireAuthenticatedEvent($user)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\Authenticated($user));
        }
    }
    protected function updateSession($id)
    {
        $this->session->set($this->getName(), $id);
        $this->session->migrate(true);
    }
    public function loginUsingId($id, $remember = false)
    {
        $user = $this->provider->retrieveById($id);
        if (!is_null($user)) {
            $this->login($user, $remember);
            return $user;
        }
        return false;
    }
    public function onceUsingId($id)
    {
        $user = $this->provider->retrieveById($id);
        if (!is_null($user)) {
            $this->setUser($user);
            return $user;
        }
        return false;
    }
    protected function queueRecallerCookie(AuthenticatableContract $user)
    {
        $value = $user->getAuthIdentifier() . '|' . $user->getRememberToken();
        $this->getCookieJar()->queue($this->createRecaller($value));
    }
    protected function createRecaller($value)
    {
        return $this->getCookieJar()->forever($this->getRecallerName(), $value);
    }
    public function logout()
    {
        $user = $this->user();
        $this->clearUserDataFromStorage();
        if (!is_null($this->user)) {
            $this->refreshRememberToken($user);
        }
        if (isset($this->events)) {
            $this->events->fire(new Events\Logout($user));
        }
        $this->user = null;
        $this->loggedOut = true;
    }
    protected function clearUserDataFromStorage()
    {
        $this->session->remove($this->getName());
        if (!is_null($this->getRecaller())) {
            $recaller = $this->getRecallerName();
            $this->getCookieJar()->queue($this->getCookieJar()->forget($recaller));
        }
    }
    protected function refreshRememberToken(AuthenticatableContract $user)
    {
        $user->setRememberToken($token = Str::random(60));
        $this->provider->updateRememberToken($user, $token);
    }
    protected function createRememberTokenIfDoesntExist(AuthenticatableContract $user)
    {
        if (empty($user->getRememberToken())) {
            $this->refreshRememberToken($user);
        }
    }
    public function getCookieJar()
    {
        if (!isset($this->cookie)) {
            throw new RuntimeException('Cookie jar has not been set.');
        }
        return $this->cookie;
    }
    public function setCookieJar(CookieJar $cookie)
    {
        $this->cookie = $cookie;
    }
    public function getDispatcher()
    {
        return $this->events;
    }
    public function setDispatcher(Dispatcher $events)
    {
        $this->events = $events;
    }
    public function getSession()
    {
        return $this->session;
    }
    public function getProvider()
    {
        return $this->provider;
    }
    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;
    }
    public function getUser()
    {
        return $this->user;
    }
    public function setUser(AuthenticatableContract $user)
    {
        $this->user = $user;
        $this->loggedOut = false;
        $this->fireAuthenticatedEvent($user);
        return $this;
    }
    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }
    public function setRequest(Request $request)
    {
        $this->request = $request;
        return $this;
    }
    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }
    public function getName()
    {
        return 'login_' . $this->name . '_' . sha1(static::class);
    }
    public function getRecallerName()
    {
        return 'remember_' . $this->name . '_' . sha1(static::class);
    }
    public function viaRemember()
    {
        return $this->viaRemember;
    }
}
}

namespace Illuminate\Auth\Access {
use Illuminate\Support\Str;
use InvalidArgumentException;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
class Gate implements GateContract
{
    use HandlesAuthorization;
    protected $container;
    protected $userResolver;
    protected $abilities = [];
    protected $policies = [];
    protected $beforeCallbacks = [];
    protected $afterCallbacks = [];
    public function __construct(Container $container, callable $userResolver, array $abilities = [], array $policies = [], array $beforeCallbacks = [], array $afterCallbacks = [])
    {
        $this->policies = $policies;
        $this->container = $container;
        $this->abilities = $abilities;
        $this->userResolver = $userResolver;
        $this->afterCallbacks = $afterCallbacks;
        $this->beforeCallbacks = $beforeCallbacks;
    }
    public function has($ability)
    {
        return isset($this->abilities[$ability]);
    }
    public function define($ability, $callback)
    {
        if (is_callable($callback)) {
            $this->abilities[$ability] = $callback;
        } elseif (is_string($callback) && Str::contains($callback, '@')) {
            $this->abilities[$ability] = $this->buildAbilityCallback($callback);
        } else {
            throw new InvalidArgumentException("Callback must be a callable or a 'Class@method' string.");
        }
        return $this;
    }
    protected function buildAbilityCallback($callback)
    {
        return function () use($callback) {
            list($class, $method) = explode('@', $callback);
            return $this->resolvePolicy($class)->{$method}(...func_get_args());
        };
    }
    public function policy($class, $policy)
    {
        $this->policies[$class] = $policy;
        return $this;
    }
    public function before(callable $callback)
    {
        $this->beforeCallbacks[] = $callback;
        return $this;
    }
    public function after(callable $callback)
    {
        $this->afterCallbacks[] = $callback;
        return $this;
    }
    public function allows($ability, $arguments = [])
    {
        return $this->check($ability, $arguments);
    }
    public function denies($ability, $arguments = [])
    {
        return !$this->allows($ability, $arguments);
    }
    public function check($ability, $arguments = [])
    {
        try {
            $result = $this->raw($ability, $arguments);
        } catch (AuthorizationException $e) {
            return false;
        }
        return (bool) $result;
    }
    public function authorize($ability, $arguments = [])
    {
        $result = $this->raw($ability, $arguments);
        if ($result instanceof Response) {
            return $result;
        }
        return $result ? $this->allow() : $this->deny();
    }
    protected function raw($ability, $arguments = [])
    {
        if (!($user = $this->resolveUser())) {
            return false;
        }
        $arguments = is_array($arguments) ? $arguments : [$arguments];
        if (is_null($result = $this->callBeforeCallbacks($user, $ability, $arguments))) {
            $result = $this->callAuthCallback($user, $ability, $arguments);
        }
        $this->callAfterCallbacks($user, $ability, $arguments, $result);
        return $result;
    }
    protected function callAuthCallback($user, $ability, array $arguments)
    {
        $callback = $this->resolveAuthCallback($user, $ability, $arguments);
        return $callback($user, ...$arguments);
    }
    protected function callBeforeCallbacks($user, $ability, array $arguments)
    {
        $arguments = array_merge([$user, $ability], [$arguments]);
        foreach ($this->beforeCallbacks as $before) {
            if (!is_null($result = $before(...$arguments))) {
                return $result;
            }
        }
    }
    protected function callAfterCallbacks($user, $ability, array $arguments, $result)
    {
        $arguments = array_merge([$user, $ability, $result], [$arguments]);
        foreach ($this->afterCallbacks as $after) {
            $after(...$arguments);
        }
    }
    protected function resolveAuthCallback($user, $ability, array $arguments)
    {
        if ($this->firstArgumentCorrespondsToPolicy($arguments)) {
            return $this->resolvePolicyCallback($user, $ability, $arguments);
        } elseif (isset($this->abilities[$ability])) {
            return $this->abilities[$ability];
        } else {
            return function () {
                return false;
            };
        }
    }
    protected function firstArgumentCorrespondsToPolicy(array $arguments)
    {
        if (!isset($arguments[0])) {
            return false;
        }
        if (is_object($arguments[0])) {
            return isset($this->policies[get_class($arguments[0])]);
        }
        return is_string($arguments[0]) && isset($this->policies[$arguments[0]]);
    }
    protected function resolvePolicyCallback($user, $ability, array $arguments)
    {
        return function () use($user, $ability, $arguments) {
            $instance = $this->getPolicyFor($arguments[0]);
            if (method_exists($instance, 'before')) {
                if (!is_null($result = $instance->before($user, $ability, ...$arguments))) {
                    return $result;
                }
            }
            if (strpos($ability, '-') !== false) {
                $ability = Str::camel($ability);
            }
            if (isset($arguments[0]) && is_string($arguments[0])) {
                array_shift($arguments);
            }
            if (!is_callable([$instance, $ability])) {
                return false;
            }
            return $instance->{$ability}($user, ...$arguments);
        };
    }
    public function getPolicyFor($class)
    {
        if (is_object($class)) {
            $class = get_class($class);
        }
        if (!isset($this->policies[$class])) {
            throw new InvalidArgumentException("Policy not defined for [{$class}].");
        }
        return $this->resolvePolicy($this->policies[$class]);
    }
    public function resolvePolicy($class)
    {
        return $this->container->make($class);
    }
    public function forUser($user)
    {
        $callback = function () use($user) {
            return $user;
        };
        return new static($this->container, $callback, $this->abilities, $this->policies, $this->beforeCallbacks, $this->afterCallbacks);
    }
    protected function resolveUser()
    {
        return call_user_func($this->userResolver);
    }
}
}

namespace Illuminate\Auth {
use Illuminate\Support\Str;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Contracts\Auth\Authenticatable as UserContract;
class EloquentUserProvider implements UserProvider
{
    protected $hasher;
    protected $model;
    public function __construct(HasherContract $hasher, $model)
    {
        $this->model = $model;
        $this->hasher = $hasher;
    }
    public function retrieveById($identifier)
    {
        return $this->createModel()->newQuery()->find($identifier);
    }
    public function retrieveByToken($identifier, $token)
    {
        $model = $this->createModel();
        return $model->newQuery()->where($model->getAuthIdentifierName(), $identifier)->where($model->getRememberTokenName(), $token)->first();
    }
    public function updateRememberToken(UserContract $user, $token)
    {
        $user->setRememberToken($token);
        $user->save();
    }
    public function retrieveByCredentials(array $credentials)
    {
        if (empty($credentials)) {
            return;
        }
        $query = $this->createModel()->newQuery();
        foreach ($credentials as $key => $value) {
            if (!Str::contains($key, 'password')) {
                $query->where($key, $value);
            }
        }
        return $query->first();
    }
    public function validateCredentials(UserContract $user, array $credentials)
    {
        $plain = $credentials['password'];
        return $this->hasher->check($plain, $user->getAuthPassword());
    }
    public function createModel()
    {
        $class = '\\' . ltrim($this->model, '\\');
        return new $class();
    }
    public function getHasher()
    {
        return $this->hasher;
    }
    public function setHasher(HasherContract $hasher)
    {
        $this->hasher = $hasher;
        return $this;
    }
    public function getModel()
    {
        return $this->model;
    }
    public function setModel($model)
    {
        $this->model = $model;
        return $this;
    }
}
}

namespace Illuminate\Auth {
use Illuminate\Auth\Access\Gate;
use Illuminate\Support\ServiceProvider;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
class AuthServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->registerAuthenticator();
        $this->registerUserResolver();
        $this->registerAccessGate();
        $this->registerRequestRebindHandler();
    }
    protected function registerAuthenticator()
    {
        $this->app->singleton('auth', function ($app) {
            $app['auth.loaded'] = true;
            return new AuthManager($app);
        });
        $this->app->singleton('auth.driver', function ($app) {
            return $app['auth']->guard();
        });
    }
    protected function registerUserResolver()
    {
        $this->app->bind(AuthenticatableContract::class, function ($app) {
            return call_user_func($app['auth']->userResolver());
        });
    }
    protected function registerAccessGate()
    {
        $this->app->singleton(GateContract::class, function ($app) {
            return new Gate($app, function () use($app) {
                return call_user_func($app['auth']->userResolver());
            });
        });
    }
    protected function registerRequestRebindHandler()
    {
        $this->app->rebinding('request', function ($app, $request) {
            $request->setUserResolver(function ($guard = null) use($app) {
                return call_user_func($app['auth']->userResolver(), $guard);
            });
        });
    }
}
}

namespace Illuminate\Container {
use Closure;
use ArrayAccess;
use LogicException;
use ReflectionClass;
use ReflectionMethod;
use ReflectionFunction;
use ReflectionParameter;
use InvalidArgumentException;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Contracts\Container\Container as ContainerContract;
class Container implements ArrayAccess, ContainerContract
{
    protected static $instance;
    protected $resolved = [];
    protected $bindings = [];
    protected $instances = [];
    protected $aliases = [];
    protected $extenders = [];
    protected $tags = [];
    protected $buildStack = [];
    public $contextual = [];
    protected $reboundCallbacks = [];
    protected $globalResolvingCallbacks = [];
    protected $globalAfterResolvingCallbacks = [];
    protected $resolvingCallbacks = [];
    protected $afterResolvingCallbacks = [];
    public function when($concrete)
    {
        $concrete = $this->normalize($concrete);
        return new ContextualBindingBuilder($this, $concrete);
    }
    public function bound($abstract)
    {
        $abstract = $this->normalize($abstract);
        return isset($this->bindings[$abstract]) || isset($this->instances[$abstract]) || $this->isAlias($abstract);
    }
    public function resolved($abstract)
    {
        $abstract = $this->normalize($abstract);
        if ($this->isAlias($abstract)) {
            $abstract = $this->getAlias($abstract);
        }
        return isset($this->resolved[$abstract]) || isset($this->instances[$abstract]);
    }
    public function isAlias($name)
    {
        return isset($this->aliases[$this->normalize($name)]);
    }
    public function bind($abstract, $concrete = null, $shared = false)
    {
        $abstract = $this->normalize($abstract);
        $concrete = $this->normalize($concrete);
        if (is_array($abstract)) {
            list($abstract, $alias) = $this->extractAlias($abstract);
            $this->alias($abstract, $alias);
        }
        $this->dropStaleInstances($abstract);
        if (is_null($concrete)) {
            $concrete = $abstract;
        }
        if (!$concrete instanceof Closure) {
            $concrete = $this->getClosure($abstract, $concrete);
        }
        $this->bindings[$abstract] = compact('concrete', 'shared');
        if ($this->resolved($abstract)) {
            $this->rebound($abstract);
        }
    }
    protected function getClosure($abstract, $concrete)
    {
        return function ($container, $parameters = []) use($abstract, $concrete) {
            $method = $abstract == $concrete ? 'build' : 'make';
            return $container->{$method}($concrete, $parameters);
        };
    }
    public function addContextualBinding($concrete, $abstract, $implementation)
    {
        $this->contextual[$this->normalize($concrete)][$this->normalize($abstract)] = $this->normalize($implementation);
    }
    public function bindIf($abstract, $concrete = null, $shared = false)
    {
        if (!$this->bound($abstract)) {
            $this->bind($abstract, $concrete, $shared);
        }
    }
    public function singleton($abstract, $concrete = null)
    {
        $this->bind($abstract, $concrete, true);
    }
    public function share(Closure $closure)
    {
        return function ($container) use($closure) {
            static $object;
            if (is_null($object)) {
                $object = $closure($container);
            }
            return $object;
        };
    }
    public function extend($abstract, Closure $closure)
    {
        $abstract = $this->normalize($abstract);
        if (isset($this->instances[$abstract])) {
            $this->instances[$abstract] = $closure($this->instances[$abstract], $this);
            $this->rebound($abstract);
        } else {
            $this->extenders[$abstract][] = $closure;
        }
    }
    public function instance($abstract, $instance)
    {
        $abstract = $this->normalize($abstract);
        if (is_array($abstract)) {
            list($abstract, $alias) = $this->extractAlias($abstract);
            $this->alias($abstract, $alias);
        }
        unset($this->aliases[$abstract]);
        $bound = $this->bound($abstract);
        $this->instances[$abstract] = $instance;
        if ($bound) {
            $this->rebound($abstract);
        }
    }
    public function tag($abstracts, $tags)
    {
        $tags = is_array($tags) ? $tags : array_slice(func_get_args(), 1);
        foreach ($tags as $tag) {
            if (!isset($this->tags[$tag])) {
                $this->tags[$tag] = [];
            }
            foreach ((array) $abstracts as $abstract) {
                $this->tags[$tag][] = $this->normalize($abstract);
            }
        }
    }
    public function tagged($tag)
    {
        $results = [];
        if (isset($this->tags[$tag])) {
            foreach ($this->tags[$tag] as $abstract) {
                $results[] = $this->make($abstract);
            }
        }
        return $results;
    }
    public function alias($abstract, $alias)
    {
        $this->aliases[$alias] = $this->normalize($abstract);
    }
    protected function extractAlias(array $definition)
    {
        return [key($definition), current($definition)];
    }
    public function rebinding($abstract, Closure $callback)
    {
        $this->reboundCallbacks[$this->normalize($abstract)][] = $callback;
        if ($this->bound($abstract)) {
            return $this->make($abstract);
        }
    }
    public function refresh($abstract, $target, $method)
    {
        return $this->rebinding($this->normalize($abstract), function ($app, $instance) use($target, $method) {
            $target->{$method}($instance);
        });
    }
    protected function rebound($abstract)
    {
        $instance = $this->make($abstract);
        foreach ($this->getReboundCallbacks($abstract) as $callback) {
            call_user_func($callback, $this, $instance);
        }
    }
    protected function getReboundCallbacks($abstract)
    {
        if (isset($this->reboundCallbacks[$abstract])) {
            return $this->reboundCallbacks[$abstract];
        }
        return [];
    }
    public function wrap(Closure $callback, array $parameters = [])
    {
        return function () use($callback, $parameters) {
            return $this->call($callback, $parameters);
        };
    }
    public function call($callback, array $parameters = [], $defaultMethod = null)
    {
        if ($this->isCallableWithAtSign($callback) || $defaultMethod) {
            return $this->callClass($callback, $parameters, $defaultMethod);
        }
        $dependencies = $this->getMethodDependencies($callback, $parameters);
        return call_user_func_array($callback, $dependencies);
    }
    protected function isCallableWithAtSign($callback)
    {
        return is_string($callback) && strpos($callback, '@') !== false;
    }
    protected function getMethodDependencies($callback, array $parameters = [])
    {
        $dependencies = [];
        foreach ($this->getCallReflector($callback)->getParameters() as $parameter) {
            $this->addDependencyForCallParameter($parameter, $parameters, $dependencies);
        }
        return array_merge($dependencies, $parameters);
    }
    protected function getCallReflector($callback)
    {
        if (is_string($callback) && strpos($callback, '::') !== false) {
            $callback = explode('::', $callback);
        }
        if (is_array($callback)) {
            return new ReflectionMethod($callback[0], $callback[1]);
        }
        return new ReflectionFunction($callback);
    }
    protected function addDependencyForCallParameter(ReflectionParameter $parameter, array &$parameters, &$dependencies)
    {
        if (array_key_exists($parameter->name, $parameters)) {
            $dependencies[] = $parameters[$parameter->name];
            unset($parameters[$parameter->name]);
        } elseif ($parameter->getClass()) {
            $dependencies[] = $this->make($parameter->getClass()->name);
        } elseif ($parameter->isDefaultValueAvailable()) {
            $dependencies[] = $parameter->getDefaultValue();
        }
    }
    protected function callClass($target, array $parameters = [], $defaultMethod = null)
    {
        $segments = explode('@', $target);
        $method = count($segments) == 2 ? $segments[1] : $defaultMethod;
        if (is_null($method)) {
            throw new InvalidArgumentException('Method not provided.');
        }
        return $this->call([$this->make($segments[0]), $method], $parameters);
    }
    public function factory($abstract, array $defaults = [])
    {
        return function (array $params = []) use($abstract, $defaults) {
            return $this->make($abstract, $params + $defaults);
        };
    }
    public function make($abstract, array $parameters = [])
    {
        $abstract = $this->getAlias($this->normalize($abstract));
        if (isset($this->instances[$abstract])) {
            return $this->instances[$abstract];
        }
        $concrete = $this->getConcrete($abstract);
        if ($this->isBuildable($concrete, $abstract)) {
            $object = $this->build($concrete, $parameters);
        } else {
            $object = $this->make($concrete, $parameters);
        }
        foreach ($this->getExtenders($abstract) as $extender) {
            $object = $extender($object, $this);
        }
        if ($this->isShared($abstract)) {
            $this->instances[$abstract] = $object;
        }
        $this->fireResolvingCallbacks($abstract, $object);
        $this->resolved[$abstract] = true;
        return $object;
    }
    protected function getConcrete($abstract)
    {
        if (!is_null($concrete = $this->getContextualConcrete($abstract))) {
            return $concrete;
        }
        if (!isset($this->bindings[$abstract])) {
            return $abstract;
        }
        return $this->bindings[$abstract]['concrete'];
    }
    protected function getContextualConcrete($abstract)
    {
        if (isset($this->contextual[end($this->buildStack)][$abstract])) {
            return $this->contextual[end($this->buildStack)][$abstract];
        }
    }
    protected function normalize($service)
    {
        return is_string($service) ? ltrim($service, '\\') : $service;
    }
    protected function getExtenders($abstract)
    {
        if (isset($this->extenders[$abstract])) {
            return $this->extenders[$abstract];
        }
        return [];
    }
    public function build($concrete, array $parameters = [])
    {
        if ($concrete instanceof Closure) {
            return $concrete($this, $parameters);
        }
        $reflector = new ReflectionClass($concrete);
        if (!$reflector->isInstantiable()) {
            if (!empty($this->buildStack)) {
                $previous = implode(', ', $this->buildStack);
                $message = "Target [{$concrete}] is not instantiable while building [{$previous}].";
            } else {
                $message = "Target [{$concrete}] is not instantiable.";
            }
            throw new BindingResolutionException($message);
        }
        $this->buildStack[] = $concrete;
        $constructor = $reflector->getConstructor();
        if (is_null($constructor)) {
            array_pop($this->buildStack);
            return new $concrete();
        }
        $dependencies = $constructor->getParameters();
        $parameters = $this->keyParametersByArgument($dependencies, $parameters);
        $instances = $this->getDependencies($dependencies, $parameters);
        array_pop($this->buildStack);
        return $reflector->newInstanceArgs($instances);
    }
    protected function getDependencies(array $parameters, array $primitives = [])
    {
        $dependencies = [];
        foreach ($parameters as $parameter) {
            $dependency = $parameter->getClass();
            if (array_key_exists($parameter->name, $primitives)) {
                $dependencies[] = $primitives[$parameter->name];
            } elseif (is_null($dependency)) {
                $dependencies[] = $this->resolveNonClass($parameter);
            } else {
                $dependencies[] = $this->resolveClass($parameter);
            }
        }
        return $dependencies;
    }
    protected function resolveNonClass(ReflectionParameter $parameter)
    {
        if (!is_null($concrete = $this->getContextualConcrete('$' . $parameter->name))) {
            if ($concrete instanceof Closure) {
                return call_user_func($concrete, $this);
            } else {
                return $concrete;
            }
        }
        if ($parameter->isDefaultValueAvailable()) {
            return $parameter->getDefaultValue();
        }
        $message = "Unresolvable dependency resolving [{$parameter}] in class {$parameter->getDeclaringClass()->getName()}";
        throw new BindingResolutionException($message);
    }
    protected function resolveClass(ReflectionParameter $parameter)
    {
        try {
            return $this->make($parameter->getClass()->name);
        } catch (BindingResolutionException $e) {
            if ($parameter->isOptional()) {
                return $parameter->getDefaultValue();
            }
            throw $e;
        }
    }
    protected function keyParametersByArgument(array $dependencies, array $parameters)
    {
        foreach ($parameters as $key => $value) {
            if (is_numeric($key)) {
                unset($parameters[$key]);
                $parameters[$dependencies[$key]->name] = $value;
            }
        }
        return $parameters;
    }
    public function resolving($abstract, Closure $callback = null)
    {
        if (is_null($callback) && $abstract instanceof Closure) {
            $this->resolvingCallback($abstract);
        } else {
            $this->resolvingCallbacks[$this->normalize($abstract)][] = $callback;
        }
    }
    public function afterResolving($abstract, Closure $callback = null)
    {
        if ($abstract instanceof Closure && is_null($callback)) {
            $this->afterResolvingCallback($abstract);
        } else {
            $this->afterResolvingCallbacks[$this->normalize($abstract)][] = $callback;
        }
    }
    protected function resolvingCallback(Closure $callback)
    {
        $abstract = $this->getFunctionHint($callback);
        if ($abstract) {
            $this->resolvingCallbacks[$abstract][] = $callback;
        } else {
            $this->globalResolvingCallbacks[] = $callback;
        }
    }
    protected function afterResolvingCallback(Closure $callback)
    {
        $abstract = $this->getFunctionHint($callback);
        if ($abstract) {
            $this->afterResolvingCallbacks[$abstract][] = $callback;
        } else {
            $this->globalAfterResolvingCallbacks[] = $callback;
        }
    }
    protected function getFunctionHint(Closure $callback)
    {
        $function = new ReflectionFunction($callback);
        if ($function->getNumberOfParameters() == 0) {
            return;
        }
        $expected = $function->getParameters()[0];
        if (!$expected->getClass()) {
            return;
        }
        return $expected->getClass()->name;
    }
    protected function fireResolvingCallbacks($abstract, $object)
    {
        $this->fireCallbackArray($object, $this->globalResolvingCallbacks);
        $this->fireCallbackArray($object, $this->getCallbacksForType($abstract, $object, $this->resolvingCallbacks));
        $this->fireCallbackArray($object, $this->globalAfterResolvingCallbacks);
        $this->fireCallbackArray($object, $this->getCallbacksForType($abstract, $object, $this->afterResolvingCallbacks));
    }
    protected function getCallbacksForType($abstract, $object, array $callbacksPerType)
    {
        $results = [];
        foreach ($callbacksPerType as $type => $callbacks) {
            if ($type === $abstract || $object instanceof $type) {
                $results = array_merge($results, $callbacks);
            }
        }
        return $results;
    }
    protected function fireCallbackArray($object, array $callbacks)
    {
        foreach ($callbacks as $callback) {
            $callback($object, $this);
        }
    }
    public function isShared($abstract)
    {
        $abstract = $this->normalize($abstract);
        if (isset($this->instances[$abstract])) {
            return true;
        }
        if (!isset($this->bindings[$abstract]['shared'])) {
            return false;
        }
        return $this->bindings[$abstract]['shared'] === true;
    }
    protected function isBuildable($concrete, $abstract)
    {
        return $concrete === $abstract || $concrete instanceof Closure;
    }
    public function getAlias($abstract)
    {
        if (!isset($this->aliases[$abstract])) {
            return $abstract;
        }
        if ($this->aliases[$abstract] === $abstract) {
            throw new LogicException("[{$abstract}] is aliased to itself.");
        }
        return $this->getAlias($this->aliases[$abstract]);
    }
    public function getBindings()
    {
        return $this->bindings;
    }
    protected function dropStaleInstances($abstract)
    {
        unset($this->instances[$abstract], $this->aliases[$abstract]);
    }
    public function forgetInstance($abstract)
    {
        unset($this->instances[$this->normalize($abstract)]);
    }
    public function forgetInstances()
    {
        $this->instances = [];
    }
    public function flush()
    {
        $this->aliases = [];
        $this->resolved = [];
        $this->bindings = [];
        $this->instances = [];
    }
    public static function getInstance()
    {
        if (is_null(static::$instance)) {
            static::$instance = new static();
        }
        return static::$instance;
    }
    public static function setInstance(ContainerContract $container = null)
    {
        return static::$instance = $container;
    }
    public function offsetExists($key)
    {
        return $this->bound($key);
    }
    public function offsetGet($key)
    {
        return $this->make($key);
    }
    public function offsetSet($key, $value)
    {
        if (!$value instanceof Closure) {
            $value = function () use($value) {
                return $value;
            };
        }
        $this->bind($key, $value);
    }
    public function offsetUnset($key)
    {
        $key = $this->normalize($key);
        unset($this->bindings[$key], $this->instances[$key], $this->resolved[$key]);
    }
    public function __get($key)
    {
        return $this[$key];
    }
    public function __set($key, $value)
    {
        $this[$key] = $value;
    }
}
}

namespace Symfony\Component\HttpKernel {
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
interface HttpKernelInterface
{
    const MASTER_REQUEST = 1;
    const SUB_REQUEST = 2;
    public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = true);
}
}

namespace Symfony\Component\HttpKernel {
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
interface TerminableInterface
{
    public function terminate(Request $request, Response $response);
}
}

namespace Illuminate\Http {
use Exception;
use Illuminate\Http\Exception\HttpResponseException;
trait ResponseTrait
{
    public $exception;
    public function status()
    {
        return $this->getStatusCode();
    }
    public function content()
    {
        return $this->getContent();
    }
    public function header($key, $values, $replace = true)
    {
        $this->headers->set($key, $values, $replace);
        return $this;
    }
    public function withHeaders(array $headers)
    {
        foreach ($headers as $key => $value) {
            $this->headers->set($key, $value);
        }
        return $this;
    }
    public function cookie($cookie)
    {
        return call_user_func_array([$this, 'withCookie'], func_get_args());
    }
    public function withCookie($cookie)
    {
        if (is_string($cookie) && function_exists('cookie')) {
            $cookie = call_user_func_array('cookie', func_get_args());
        }
        $this->headers->setCookie($cookie);
        return $this;
    }
    public function withException(Exception $e)
    {
        $this->exception = $e;
        return $this;
    }
    public function throwResponse()
    {
        throw new HttpResponseException($this);
    }
}
}

namespace Illuminate\Http {
use ArrayObject;
use JsonSerializable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Renderable;
use Symfony\Component\HttpFoundation\Response as BaseResponse;
class Response extends BaseResponse
{
    use ResponseTrait;
    public $original;
    public function setContent($content)
    {
        $this->original = $content;
        if ($this->shouldBeJson($content)) {
            $this->header('Content-Type', 'application/json');
            $content = $this->morphToJson($content);
        } elseif ($content instanceof Renderable) {
            $content = $content->render();
        }
        return parent::setContent($content);
    }
    protected function morphToJson($content)
    {
        if ($content instanceof Jsonable) {
            return $content->toJson();
        }
        return json_encode($content);
    }
    protected function shouldBeJson($content)
    {
        return $content instanceof Jsonable || $content instanceof ArrayObject || $content instanceof JsonSerializable || is_array($content);
    }
    public function getOriginalContent()
    {
        return $this->original;
    }
}
}

namespace Illuminate\Http\Middleware {
use Closure;
class FrameGuard
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);
        $response->headers->set('X-Frame-Options', 'SAMEORIGIN', false);
        return $response;
    }
}
}

namespace Symfony\Component\HttpFoundation {
class ParameterBag implements \IteratorAggregate, \Countable
{
    protected $parameters;
    public function __construct(array $parameters = array())
    {
        $this->parameters = $parameters;
    }
    public function all()
    {
        return $this->parameters;
    }
    public function keys()
    {
        return array_keys($this->parameters);
    }
    public function replace(array $parameters = array())
    {
        $this->parameters = $parameters;
    }
    public function add(array $parameters = array())
    {
        $this->parameters = array_replace($this->parameters, $parameters);
    }
    public function get($key, $default = null)
    {
        return array_key_exists($key, $this->parameters) ? $this->parameters[$key] : $default;
    }
    public function set($key, $value)
    {
        $this->parameters[$key] = $value;
    }
    public function has($key)
    {
        return array_key_exists($key, $this->parameters);
    }
    public function remove($key)
    {
        unset($this->parameters[$key]);
    }
    public function getAlpha($key, $default = '')
    {
        return preg_replace('/[^[:alpha:]]/', '', $this->get($key, $default));
    }
    public function getAlnum($key, $default = '')
    {
        return preg_replace('/[^[:alnum:]]/', '', $this->get($key, $default));
    }
    public function getDigits($key, $default = '')
    {
        return str_replace(array('-', '+'), '', $this->filter($key, $default, FILTER_SANITIZE_NUMBER_INT));
    }
    public function getInt($key, $default = 0)
    {
        return (int) $this->get($key, $default);
    }
    public function getBoolean($key, $default = false)
    {
        return $this->filter($key, $default, FILTER_VALIDATE_BOOLEAN);
    }
    public function filter($key, $default = null, $filter = FILTER_DEFAULT, $options = array())
    {
        $value = $this->get($key, $default);
        if (!is_array($options) && $options) {
            $options = array('flags' => $options);
        }
        if (is_array($value) && !isset($options['flags'])) {
            $options['flags'] = FILTER_REQUIRE_ARRAY;
        }
        return filter_var($value, $filter, $options);
    }
    public function getIterator()
    {
        return new \ArrayIterator($this->parameters);
    }
    public function count()
    {
        return count($this->parameters);
    }
}
}

namespace Symfony\Component\HttpFoundation {
use Symfony\Component\HttpFoundation\File\UploadedFile;
class FileBag extends ParameterBag
{
    private static $fileKeys = array('error', 'name', 'size', 'tmp_name', 'type');
    public function __construct(array $parameters = array())
    {
        $this->replace($parameters);
    }
    public function replace(array $files = array())
    {
        $this->parameters = array();
        $this->add($files);
    }
    public function set($key, $value)
    {
        if (!is_array($value) && !$value instanceof UploadedFile) {
            throw new \InvalidArgumentException('An uploaded file must be an array or an instance of UploadedFile.');
        }
        parent::set($key, $this->convertFileInformation($value));
    }
    public function add(array $files = array())
    {
        foreach ($files as $key => $file) {
            $this->set($key, $file);
        }
    }
    protected function convertFileInformation($file)
    {
        if ($file instanceof UploadedFile) {
            return $file;
        }
        $file = $this->fixPhpFilesArray($file);
        if (is_array($file)) {
            $keys = array_keys($file);
            sort($keys);
            if ($keys == self::$fileKeys) {
                if (UPLOAD_ERR_NO_FILE == $file['error']) {
                    $file = null;
                } else {
                    $file = new UploadedFile($file['tmp_name'], $file['name'], $file['type'], $file['size'], $file['error']);
                }
            } else {
                $file = array_map(array($this, 'convertFileInformation'), $file);
            }
        }
        return $file;
    }
    protected function fixPhpFilesArray($data)
    {
        if (!is_array($data)) {
            return $data;
        }
        $keys = array_keys($data);
        sort($keys);
        if (self::$fileKeys != $keys || !isset($data['name']) || !is_array($data['name'])) {
            return $data;
        }
        $files = $data;
        foreach (self::$fileKeys as $k) {
            unset($files[$k]);
        }
        foreach ($data['name'] as $key => $name) {
            $files[$key] = $this->fixPhpFilesArray(array('error' => $data['error'][$key], 'name' => $name, 'type' => $data['type'][$key], 'tmp_name' => $data['tmp_name'][$key], 'size' => $data['size'][$key]));
        }
        return $files;
    }
}
}

namespace Symfony\Component\HttpFoundation {
class ServerBag extends ParameterBag
{
    public function getHeaders()
    {
        $headers = array();
        $contentHeaders = array('CONTENT_LENGTH' => true, 'CONTENT_MD5' => true, 'CONTENT_TYPE' => true);
        foreach ($this->parameters as $key => $value) {
            if (0 === strpos($key, 'HTTP_')) {
                $headers[substr($key, 5)] = $value;
            } elseif (isset($contentHeaders[$key])) {
                $headers[$key] = $value;
            }
        }
        if (isset($this->parameters['PHP_AUTH_USER'])) {
            $headers['PHP_AUTH_USER'] = $this->parameters['PHP_AUTH_USER'];
            $headers['PHP_AUTH_PW'] = isset($this->parameters['PHP_AUTH_PW']) ? $this->parameters['PHP_AUTH_PW'] : '';
        } else {
            $authorizationHeader = null;
            if (isset($this->parameters['HTTP_AUTHORIZATION'])) {
                $authorizationHeader = $this->parameters['HTTP_AUTHORIZATION'];
            } elseif (isset($this->parameters['REDIRECT_HTTP_AUTHORIZATION'])) {
                $authorizationHeader = $this->parameters['REDIRECT_HTTP_AUTHORIZATION'];
            }
            if (null !== $authorizationHeader) {
                if (0 === stripos($authorizationHeader, 'basic ')) {
                    $exploded = explode(':', base64_decode(substr($authorizationHeader, 6)), 2);
                    if (count($exploded) == 2) {
                        list($headers['PHP_AUTH_USER'], $headers['PHP_AUTH_PW']) = $exploded;
                    }
                } elseif (empty($this->parameters['PHP_AUTH_DIGEST']) && 0 === stripos($authorizationHeader, 'digest ')) {
                    $headers['PHP_AUTH_DIGEST'] = $authorizationHeader;
                    $this->parameters['PHP_AUTH_DIGEST'] = $authorizationHeader;
                } elseif (0 === stripos($authorizationHeader, 'bearer ')) {
                    $headers['AUTHORIZATION'] = $authorizationHeader;
                }
            }
        }
        if (isset($headers['AUTHORIZATION'])) {
            return $headers;
        }
        if (isset($headers['PHP_AUTH_USER'])) {
            $headers['AUTHORIZATION'] = 'Basic ' . base64_encode($headers['PHP_AUTH_USER'] . ':' . $headers['PHP_AUTH_PW']);
        } elseif (isset($headers['PHP_AUTH_DIGEST'])) {
            $headers['AUTHORIZATION'] = $headers['PHP_AUTH_DIGEST'];
        }
        return $headers;
    }
}
}

namespace Symfony\Component\HttpFoundation {
class HeaderBag implements \IteratorAggregate, \Countable
{
    protected $headers = array();
    protected $cacheControl = array();
    public function __construct(array $headers = array())
    {
        foreach ($headers as $key => $values) {
            $this->set($key, $values);
        }
    }
    public function __toString()
    {
        if (!$this->headers) {
            return '';
        }
        $max = max(array_map('strlen', array_keys($this->headers))) + 1;
        $content = '';
        ksort($this->headers);
        foreach ($this->headers as $name => $values) {
            $name = implode('-', array_map('ucfirst', explode('-', $name)));
            foreach ($values as $value) {
                $content .= sprintf("%-{$max}s %s\r\n", $name . ':', $value);
            }
        }
        return $content;
    }
    public function all()
    {
        return $this->headers;
    }
    public function keys()
    {
        return array_keys($this->headers);
    }
    public function replace(array $headers = array())
    {
        $this->headers = array();
        $this->add($headers);
    }
    public function add(array $headers)
    {
        foreach ($headers as $key => $values) {
            $this->set($key, $values);
        }
    }
    public function get($key, $default = null, $first = true)
    {
        $key = str_replace('_', '-', strtolower($key));
        if (!array_key_exists($key, $this->headers)) {
            if (null === $default) {
                return $first ? null : array();
            }
            return $first ? $default : array($default);
        }
        if ($first) {
            return count($this->headers[$key]) ? $this->headers[$key][0] : $default;
        }
        return $this->headers[$key];
    }
    public function set($key, $values, $replace = true)
    {
        $key = str_replace('_', '-', strtolower($key));
        $values = array_values((array) $values);
        if (true === $replace || !isset($this->headers[$key])) {
            $this->headers[$key] = $values;
        } else {
            $this->headers[$key] = array_merge($this->headers[$key], $values);
        }
        if ('cache-control' === $key) {
            $this->cacheControl = $this->parseCacheControl($values[0]);
        }
    }
    public function has($key)
    {
        return array_key_exists(str_replace('_', '-', strtolower($key)), $this->headers);
    }
    public function contains($key, $value)
    {
        return in_array($value, $this->get($key, null, false));
    }
    public function remove($key)
    {
        $key = str_replace('_', '-', strtolower($key));
        unset($this->headers[$key]);
        if ('cache-control' === $key) {
            $this->cacheControl = array();
        }
    }
    public function getDate($key, \DateTime $default = null)
    {
        if (null === ($value = $this->get($key))) {
            return $default;
        }
        if (false === ($date = \DateTime::createFromFormat(DATE_RFC2822, $value))) {
            throw new \RuntimeException(sprintf('The %s HTTP header is not parseable (%s).', $key, $value));
        }
        return $date;
    }
    public function addCacheControlDirective($key, $value = true)
    {
        $this->cacheControl[$key] = $value;
        $this->set('Cache-Control', $this->getCacheControlHeader());
    }
    public function hasCacheControlDirective($key)
    {
        return array_key_exists($key, $this->cacheControl);
    }
    public function getCacheControlDirective($key)
    {
        return array_key_exists($key, $this->cacheControl) ? $this->cacheControl[$key] : null;
    }
    public function removeCacheControlDirective($key)
    {
        unset($this->cacheControl[$key]);
        $this->set('Cache-Control', $this->getCacheControlHeader());
    }
    public function getIterator()
    {
        return new \ArrayIterator($this->headers);
    }
    public function count()
    {
        return count($this->headers);
    }
    protected function getCacheControlHeader()
    {
        $parts = array();
        ksort($this->cacheControl);
        foreach ($this->cacheControl as $key => $value) {
            if (true === $value) {
                $parts[] = $key;
            } else {
                if (preg_match('#[^a-zA-Z0-9._-]#', $value)) {
                    $value = '"' . $value . '"';
                }
                $parts[] = "{$key}={$value}";
            }
        }
        return implode(', ', $parts);
    }
    protected function parseCacheControl($header)
    {
        $cacheControl = array();
        preg_match_all('#([a-zA-Z][a-zA-Z_-]*)\\s*(?:=(?:"([^"]*)"|([^ \\t",;]*)))?#', $header, $matches, PREG_SET_ORDER);
        foreach ($matches as $match) {
            $cacheControl[strtolower($match[1])] = isset($match[3]) ? $match[3] : (isset($match[2]) ? $match[2] : true);
        }
        return $cacheControl;
    }
}
}

namespace Symfony\Component\HttpFoundation\Session {
use Symfony\Component\HttpFoundation\Session\Storage\MetadataBag;
interface SessionInterface
{
    public function start();
    public function getId();
    public function setId($id);
    public function getName();
    public function setName($name);
    public function invalidate($lifetime = null);
    public function migrate($destroy = false, $lifetime = null);
    public function save();
    public function has($name);
    public function get($name, $default = null);
    public function set($name, $value);
    public function all();
    public function replace(array $attributes);
    public function remove($name);
    public function clear();
    public function isStarted();
    public function registerBag(SessionBagInterface $bag);
    public function getBag($name);
    public function getMetadataBag();
}
}

namespace Symfony\Component\HttpFoundation\Session {
interface SessionBagInterface
{
    public function getName();
    public function initialize(array &$array);
    public function getStorageKey();
    public function clear();
}
}

namespace Symfony\Component\HttpFoundation\Session\Attribute {
use Symfony\Component\HttpFoundation\Session\SessionBagInterface;
interface AttributeBagInterface extends SessionBagInterface
{
    public function has($name);
    public function get($name, $default = null);
    public function set($name, $value);
    public function all();
    public function replace(array $attributes);
    public function remove($name);
}
}

namespace Symfony\Component\HttpFoundation\Session\Attribute {
class AttributeBag implements AttributeBagInterface, \IteratorAggregate, \Countable
{
    private $name = 'attributes';
    private $storageKey;
    protected $attributes = array();
    public function __construct($storageKey = '_sf2_attributes')
    {
        $this->storageKey = $storageKey;
    }
    public function getName()
    {
        return $this->name;
    }
    public function setName($name)
    {
        $this->name = $name;
    }
    public function initialize(array &$attributes)
    {
        $this->attributes =& $attributes;
    }
    public function getStorageKey()
    {
        return $this->storageKey;
    }
    public function has($name)
    {
        return array_key_exists($name, $this->attributes);
    }
    public function get($name, $default = null)
    {
        return array_key_exists($name, $this->attributes) ? $this->attributes[$name] : $default;
    }
    public function set($name, $value)
    {
        $this->attributes[$name] = $value;
    }
    public function all()
    {
        return $this->attributes;
    }
    public function replace(array $attributes)
    {
        $this->attributes = array();
        foreach ($attributes as $key => $value) {
            $this->set($key, $value);
        }
    }
    public function remove($name)
    {
        $retval = null;
        if (array_key_exists($name, $this->attributes)) {
            $retval = $this->attributes[$name];
            unset($this->attributes[$name]);
        }
        return $retval;
    }
    public function clear()
    {
        $return = $this->attributes;
        $this->attributes = array();
        return $return;
    }
    public function getIterator()
    {
        return new \ArrayIterator($this->attributes);
    }
    public function count()
    {
        return count($this->attributes);
    }
}
}

namespace Symfony\Component\HttpFoundation\Session\Storage {
use Symfony\Component\HttpFoundation\Session\SessionBagInterface;
class MetadataBag implements SessionBagInterface
{
    const CREATED = 'c';
    const UPDATED = 'u';
    const LIFETIME = 'l';
    private $name = '__metadata';
    private $storageKey;
    protected $meta = array(self::CREATED => 0, self::UPDATED => 0, self::LIFETIME => 0);
    private $lastUsed;
    private $updateThreshold;
    public function __construct($storageKey = '_sf2_meta', $updateThreshold = 0)
    {
        $this->storageKey = $storageKey;
        $this->updateThreshold = $updateThreshold;
    }
    public function initialize(array &$array)
    {
        $this->meta =& $array;
        if (isset($array[self::CREATED])) {
            $this->lastUsed = $this->meta[self::UPDATED];
            $timeStamp = time();
            if ($timeStamp - $array[self::UPDATED] >= $this->updateThreshold) {
                $this->meta[self::UPDATED] = $timeStamp;
            }
        } else {
            $this->stampCreated();
        }
    }
    public function getLifetime()
    {
        return $this->meta[self::LIFETIME];
    }
    public function stampNew($lifetime = null)
    {
        $this->stampCreated($lifetime);
    }
    public function getStorageKey()
    {
        return $this->storageKey;
    }
    public function getCreated()
    {
        return $this->meta[self::CREATED];
    }
    public function getLastUsed()
    {
        return $this->lastUsed;
    }
    public function clear()
    {
    }
    public function getName()
    {
        return $this->name;
    }
    public function setName($name)
    {
        $this->name = $name;
    }
    private function stampCreated($lifetime = null)
    {
        $timeStamp = time();
        $this->meta[self::CREATED] = $this->meta[self::UPDATED] = $this->lastUsed = $timeStamp;
        $this->meta[self::LIFETIME] = null === $lifetime ? ini_get('session.cookie_lifetime') : $lifetime;
    }
}
}

namespace Symfony\Component\HttpFoundation {
class AcceptHeaderItem
{
    private $value;
    private $quality = 1.0;
    private $index = 0;
    private $attributes = array();
    public function __construct($value, array $attributes = array())
    {
        $this->value = $value;
        foreach ($attributes as $name => $value) {
            $this->setAttribute($name, $value);
        }
    }
    public static function fromString($itemValue)
    {
        $bits = preg_split('/\\s*(?:;*("[^"]+");*|;*(\'[^\']+\');*|;+)\\s*/', $itemValue, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
        $value = array_shift($bits);
        $attributes = array();
        $lastNullAttribute = null;
        foreach ($bits as $bit) {
            if (($start = substr($bit, 0, 1)) === ($end = substr($bit, -1)) && ($start === '"' || $start === '\'')) {
                $attributes[$lastNullAttribute] = substr($bit, 1, -1);
            } elseif ('=' === $end) {
                $lastNullAttribute = $bit = substr($bit, 0, -1);
                $attributes[$bit] = null;
            } else {
                $parts = explode('=', $bit);
                $attributes[$parts[0]] = isset($parts[1]) && strlen($parts[1]) > 0 ? $parts[1] : '';
            }
        }
        return new self(($start = substr($value, 0, 1)) === ($end = substr($value, -1)) && ($start === '"' || $start === '\'') ? substr($value, 1, -1) : $value, $attributes);
    }
    public function __toString()
    {
        $string = $this->value . ($this->quality < 1 ? ';q=' . $this->quality : '');
        if (count($this->attributes) > 0) {
            $string .= ';' . implode(';', array_map(function ($name, $value) {
                return sprintf(preg_match('/[,;=]/', $value) ? '%s="%s"' : '%s=%s', $name, $value);
            }, array_keys($this->attributes), $this->attributes));
        }
        return $string;
    }
    public function setValue($value)
    {
        $this->value = $value;
        return $this;
    }
    public function getValue()
    {
        return $this->value;
    }
    public function setQuality($quality)
    {
        $this->quality = $quality;
        return $this;
    }
    public function getQuality()
    {
        return $this->quality;
    }
    public function setIndex($index)
    {
        $this->index = $index;
        return $this;
    }
    public function getIndex()
    {
        return $this->index;
    }
    public function hasAttribute($name)
    {
        return isset($this->attributes[$name]);
    }
    public function getAttribute($name, $default = null)
    {
        return isset($this->attributes[$name]) ? $this->attributes[$name] : $default;
    }
    public function getAttributes()
    {
        return $this->attributes;
    }
    public function setAttribute($name, $value)
    {
        if ('q' === $name) {
            $this->quality = (double) $value;
        } else {
            $this->attributes[$name] = (string) $value;
        }
        return $this;
    }
}
}

namespace Symfony\Component\HttpFoundation {
class AcceptHeader
{
    private $items = array();
    private $sorted = true;
    public function __construct(array $items)
    {
        foreach ($items as $item) {
            $this->add($item);
        }
    }
    public static function fromString($headerValue)
    {
        $index = 0;
        return new self(array_map(function ($itemValue) use(&$index) {
            $item = AcceptHeaderItem::fromString($itemValue);
            $item->setIndex($index++);
            return $item;
        }, preg_split('/\\s*(?:,*("[^"]+"),*|,*(\'[^\']+\'),*|,+)\\s*/', $headerValue, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE)));
    }
    public function __toString()
    {
        return implode(',', $this->items);
    }
    public function has($value)
    {
        return isset($this->items[$value]);
    }
    public function get($value)
    {
        return isset($this->items[$value]) ? $this->items[$value] : null;
    }
    public function add(AcceptHeaderItem $item)
    {
        $this->items[$item->getValue()] = $item;
        $this->sorted = false;
        return $this;
    }
    public function all()
    {
        $this->sort();
        return $this->items;
    }
    public function filter($pattern)
    {
        return new self(array_filter($this->items, function (AcceptHeaderItem $item) use($pattern) {
            return preg_match($pattern, $item->getValue());
        }));
    }
    public function first()
    {
        $this->sort();
        return !empty($this->items) ? reset($this->items) : null;
    }
    private function sort()
    {
        if (!$this->sorted) {
            uasort($this->items, function ($a, $b) {
                $qA = $a->getQuality();
                $qB = $b->getQuality();
                if ($qA === $qB) {
                    return $a->getIndex() > $b->getIndex() ? 1 : -1;
                }
                return $qA > $qB ? -1 : 1;
            });
            $this->sorted = true;
        }
    }
}
}

namespace Symfony\Component\HttpFoundation {
class Response
{
    const HTTP_CONTINUE = 100;
    const HTTP_SWITCHING_PROTOCOLS = 101;
    const HTTP_PROCESSING = 102;
    const HTTP_OK = 200;
    const HTTP_CREATED = 201;
    const HTTP_ACCEPTED = 202;
    const HTTP_NON_AUTHORITATIVE_INFORMATION = 203;
    const HTTP_NO_CONTENT = 204;
    const HTTP_RESET_CONTENT = 205;
    const HTTP_PARTIAL_CONTENT = 206;
    const HTTP_MULTI_STATUS = 207;
    const HTTP_ALREADY_REPORTED = 208;
    const HTTP_IM_USED = 226;
    const HTTP_MULTIPLE_CHOICES = 300;
    const HTTP_MOVED_PERMANENTLY = 301;
    const HTTP_FOUND = 302;
    const HTTP_SEE_OTHER = 303;
    const HTTP_NOT_MODIFIED = 304;
    const HTTP_USE_PROXY = 305;
    const HTTP_RESERVED = 306;
    const HTTP_TEMPORARY_REDIRECT = 307;
    const HTTP_PERMANENTLY_REDIRECT = 308;
    const HTTP_BAD_REQUEST = 400;
    const HTTP_UNAUTHORIZED = 401;
    const HTTP_PAYMENT_REQUIRED = 402;
    const HTTP_FORBIDDEN = 403;
    const HTTP_NOT_FOUND = 404;
    const HTTP_METHOD_NOT_ALLOWED = 405;
    const HTTP_NOT_ACCEPTABLE = 406;
    const HTTP_PROXY_AUTHENTICATION_REQUIRED = 407;
    const HTTP_REQUEST_TIMEOUT = 408;
    const HTTP_CONFLICT = 409;
    const HTTP_GONE = 410;
    const HTTP_LENGTH_REQUIRED = 411;
    const HTTP_PRECONDITION_FAILED = 412;
    const HTTP_REQUEST_ENTITY_TOO_LARGE = 413;
    const HTTP_REQUEST_URI_TOO_LONG = 414;
    const HTTP_UNSUPPORTED_MEDIA_TYPE = 415;
    const HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416;
    const HTTP_EXPECTATION_FAILED = 417;
    const HTTP_I_AM_A_TEAPOT = 418;
    const HTTP_MISDIRECTED_REQUEST = 421;
    const HTTP_UNPROCESSABLE_ENTITY = 422;
    const HTTP_LOCKED = 423;
    const HTTP_FAILED_DEPENDENCY = 424;
    const HTTP_RESERVED_FOR_WEBDAV_ADVANCED_COLLECTIONS_EXPIRED_PROPOSAL = 425;
    const HTTP_UPGRADE_REQUIRED = 426;
    const HTTP_PRECONDITION_REQUIRED = 428;
    const HTTP_TOO_MANY_REQUESTS = 429;
    const HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE = 431;
    const HTTP_UNAVAILABLE_FOR_LEGAL_REASONS = 451;
    const HTTP_INTERNAL_SERVER_ERROR = 500;
    const HTTP_NOT_IMPLEMENTED = 501;
    const HTTP_BAD_GATEWAY = 502;
    const HTTP_SERVICE_UNAVAILABLE = 503;
    const HTTP_GATEWAY_TIMEOUT = 504;
    const HTTP_VERSION_NOT_SUPPORTED = 505;
    const HTTP_VARIANT_ALSO_NEGOTIATES_EXPERIMENTAL = 506;
    const HTTP_INSUFFICIENT_STORAGE = 507;
    const HTTP_LOOP_DETECTED = 508;
    const HTTP_NOT_EXTENDED = 510;
    const HTTP_NETWORK_AUTHENTICATION_REQUIRED = 511;
    public $headers;
    protected $content;
    protected $version;
    protected $statusCode;
    protected $statusText;
    protected $charset;
    public static $statusTexts = array(100 => 'Continue', 101 => 'Switching Protocols', 102 => 'Processing', 200 => 'OK', 201 => 'Created', 202 => 'Accepted', 203 => 'Non-Authoritative Information', 204 => 'No Content', 205 => 'Reset Content', 206 => 'Partial Content', 207 => 'Multi-Status', 208 => 'Already Reported', 226 => 'IM Used', 300 => 'Multiple Choices', 301 => 'Moved Permanently', 302 => 'Found', 303 => 'See Other', 304 => 'Not Modified', 305 => 'Use Proxy', 307 => 'Temporary Redirect', 308 => 'Permanent Redirect', 400 => 'Bad Request', 401 => 'Unauthorized', 402 => 'Payment Required', 403 => 'Forbidden', 404 => 'Not Found', 405 => 'Method Not Allowed', 406 => 'Not Acceptable', 407 => 'Proxy Authentication Required', 408 => 'Request Timeout', 409 => 'Conflict', 410 => 'Gone', 411 => 'Length Required', 412 => 'Precondition Failed', 413 => 'Payload Too Large', 414 => 'URI Too Long', 415 => 'Unsupported Media Type', 416 => 'Range Not Satisfiable', 417 => 'Expectation Failed', 418 => 'I\'m a teapot', 421 => 'Misdirected Request', 422 => 'Unprocessable Entity', 423 => 'Locked', 424 => 'Failed Dependency', 425 => 'Reserved for WebDAV advanced collections expired proposal', 426 => 'Upgrade Required', 428 => 'Precondition Required', 429 => 'Too Many Requests', 431 => 'Request Header Fields Too Large', 451 => 'Unavailable For Legal Reasons', 500 => 'Internal Server Error', 501 => 'Not Implemented', 502 => 'Bad Gateway', 503 => 'Service Unavailable', 504 => 'Gateway Timeout', 505 => 'HTTP Version Not Supported', 506 => 'Variant Also Negotiates (Experimental)', 507 => 'Insufficient Storage', 508 => 'Loop Detected', 510 => 'Not Extended', 511 => 'Network Authentication Required');
    public function __construct($content = '', $status = 200, $headers = array())
    {
        $this->headers = new ResponseHeaderBag($headers);
        $this->setContent($content);
        $this->setStatusCode($status);
        $this->setProtocolVersion('1.0');
    }
    public static function create($content = '', $status = 200, $headers = array())
    {
        return new static($content, $status, $headers);
    }
    public function __toString()
    {
        return sprintf('HTTP/%s %s %s', $this->version, $this->statusCode, $this->statusText) . "\r\n" . $this->headers . "\r\n" . $this->getContent();
    }
    public function __clone()
    {
        $this->headers = clone $this->headers;
    }
    public function prepare(Request $request)
    {
        $headers = $this->headers;
        if ($this->isInformational() || $this->isEmpty()) {
            $this->setContent(null);
            $headers->remove('Content-Type');
            $headers->remove('Content-Length');
        } else {
            if (!$headers->has('Content-Type')) {
                $format = $request->getRequestFormat();
                if (null !== $format && ($mimeType = $request->getMimeType($format))) {
                    $headers->set('Content-Type', $mimeType);
                }
            }
            $charset = $this->charset ?: 'UTF-8';
            if (!$headers->has('Content-Type')) {
                $headers->set('Content-Type', 'text/html; charset=' . $charset);
            } elseif (0 === stripos($headers->get('Content-Type'), 'text/') && false === stripos($headers->get('Content-Type'), 'charset')) {
                $headers->set('Content-Type', $headers->get('Content-Type') . '; charset=' . $charset);
            }
            if ($headers->has('Transfer-Encoding')) {
                $headers->remove('Content-Length');
            }
            if ($request->isMethod('HEAD')) {
                $length = $headers->get('Content-Length');
                $this->setContent(null);
                if ($length) {
                    $headers->set('Content-Length', $length);
                }
            }
        }
        if ('HTTP/1.0' != $request->server->get('SERVER_PROTOCOL')) {
            $this->setProtocolVersion('1.1');
        }
        if ('1.0' == $this->getProtocolVersion() && 'no-cache' == $this->headers->get('Cache-Control')) {
            $this->headers->set('pragma', 'no-cache');
            $this->headers->set('expires', -1);
        }
        $this->ensureIEOverSSLCompatibility($request);
        return $this;
    }
    public function sendHeaders()
    {
        if (headers_sent()) {
            return $this;
        }
        if (!$this->headers->has('Date')) {
            $this->setDate(\DateTime::createFromFormat('U', time()));
        }
        foreach ($this->headers->allPreserveCase() as $name => $values) {
            foreach ($values as $value) {
                header($name . ': ' . $value, false, $this->statusCode);
            }
        }
        header(sprintf('HTTP/%s %s %s', $this->version, $this->statusCode, $this->statusText), true, $this->statusCode);
        foreach ($this->headers->getCookies() as $cookie) {
            if ($cookie->isRaw()) {
                setrawcookie($cookie->getName(), $cookie->getValue(), $cookie->getExpiresTime(), $cookie->getPath(), $cookie->getDomain(), $cookie->isSecure(), $cookie->isHttpOnly());
            } else {
                setcookie($cookie->getName(), $cookie->getValue(), $cookie->getExpiresTime(), $cookie->getPath(), $cookie->getDomain(), $cookie->isSecure(), $cookie->isHttpOnly());
            }
        }
        return $this;
    }
    public function sendContent()
    {
        echo $this->content;
        return $this;
    }
    public function send()
    {
        $this->sendHeaders();
        $this->sendContent();
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        } elseif ('cli' !== PHP_SAPI) {
            static::closeOutputBuffers(0, true);
        }
        return $this;
    }
    public function setContent($content)
    {
        if (null !== $content && !is_string($content) && !is_numeric($content) && !is_callable(array($content, '__toString'))) {
            throw new \UnexpectedValueException(sprintf('The Response content must be a string or object implementing __toString(), "%s" given.', gettype($content)));
        }
        $this->content = (string) $content;
        return $this;
    }
    public function getContent()
    {
        return $this->content;
    }
    public function setProtocolVersion($version)
    {
        $this->version = $version;
        return $this;
    }
    public function getProtocolVersion()
    {
        return $this->version;
    }
    public function setStatusCode($code, $text = null)
    {
        $this->statusCode = $code = (int) $code;
        if ($this->isInvalid()) {
            throw new \InvalidArgumentException(sprintf('The HTTP status code "%s" is not valid.', $code));
        }
        if (null === $text) {
            $this->statusText = isset(self::$statusTexts[$code]) ? self::$statusTexts[$code] : 'unknown status';
            return $this;
        }
        if (false === $text) {
            $this->statusText = '';
            return $this;
        }
        $this->statusText = $text;
        return $this;
    }
    public function getStatusCode()
    {
        return $this->statusCode;
    }
    public function setCharset($charset)
    {
        $this->charset = $charset;
        return $this;
    }
    public function getCharset()
    {
        return $this->charset;
    }
    public function isCacheable()
    {
        if (!in_array($this->statusCode, array(200, 203, 300, 301, 302, 404, 410))) {
            return false;
        }
        if ($this->headers->hasCacheControlDirective('no-store') || $this->headers->getCacheControlDirective('private')) {
            return false;
        }
        return $this->isValidateable() || $this->isFresh();
    }
    public function isFresh()
    {
        return $this->getTtl() > 0;
    }
    public function isValidateable()
    {
        return $this->headers->has('Last-Modified') || $this->headers->has('ETag');
    }
    public function setPrivate()
    {
        $this->headers->removeCacheControlDirective('public');
        $this->headers->addCacheControlDirective('private');
        return $this;
    }
    public function setPublic()
    {
        $this->headers->addCacheControlDirective('public');
        $this->headers->removeCacheControlDirective('private');
        return $this;
    }
    public function mustRevalidate()
    {
        return $this->headers->hasCacheControlDirective('must-revalidate') || $this->headers->hasCacheControlDirective('proxy-revalidate');
    }
    public function getDate()
    {
        if (!$this->headers->has('Date')) {
            $this->setDate(\DateTime::createFromFormat('U', time()));
        }
        return $this->headers->getDate('Date');
    }
    public function setDate(\DateTime $date)
    {
        $date->setTimezone(new \DateTimeZone('UTC'));
        $this->headers->set('Date', $date->format('D, d M Y H:i:s') . ' GMT');
        return $this;
    }
    public function getAge()
    {
        if (null !== ($age = $this->headers->get('Age'))) {
            return (int) $age;
        }
        return max(time() - $this->getDate()->format('U'), 0);
    }
    public function expire()
    {
        if ($this->isFresh()) {
            $this->headers->set('Age', $this->getMaxAge());
        }
        return $this;
    }
    public function getExpires()
    {
        try {
            return $this->headers->getDate('Expires');
        } catch (\RuntimeException $e) {
            return \DateTime::createFromFormat(DATE_RFC2822, 'Sat, 01 Jan 00 00:00:00 +0000');
        }
    }
    public function setExpires(\DateTime $date = null)
    {
        if (null === $date) {
            $this->headers->remove('Expires');
        } else {
            $date = clone $date;
            $date->setTimezone(new \DateTimeZone('UTC'));
            $this->headers->set('Expires', $date->format('D, d M Y H:i:s') . ' GMT');
        }
        return $this;
    }
    public function getMaxAge()
    {
        if ($this->headers->hasCacheControlDirective('s-maxage')) {
            return (int) $this->headers->getCacheControlDirective('s-maxage');
        }
        if ($this->headers->hasCacheControlDirective('max-age')) {
            return (int) $this->headers->getCacheControlDirective('max-age');
        }
        if (null !== $this->getExpires()) {
            return $this->getExpires()->format('U') - $this->getDate()->format('U');
        }
    }
    public function setMaxAge($value)
    {
        $this->headers->addCacheControlDirective('max-age', $value);
        return $this;
    }
    public function setSharedMaxAge($value)
    {
        $this->setPublic();
        $this->headers->addCacheControlDirective('s-maxage', $value);
        return $this;
    }
    public function getTtl()
    {
        if (null !== ($maxAge = $this->getMaxAge())) {
            return $maxAge - $this->getAge();
        }
    }
    public function setTtl($seconds)
    {
        $this->setSharedMaxAge($this->getAge() + $seconds);
        return $this;
    }
    public function setClientTtl($seconds)
    {
        $this->setMaxAge($this->getAge() + $seconds);
        return $this;
    }
    public function getLastModified()
    {
        return $this->headers->getDate('Last-Modified');
    }
    public function setLastModified(\DateTime $date = null)
    {
        if (null === $date) {
            $this->headers->remove('Last-Modified');
        } else {
            $date = clone $date;
            $date->setTimezone(new \DateTimeZone('UTC'));
            $this->headers->set('Last-Modified', $date->format('D, d M Y H:i:s') . ' GMT');
        }
        return $this;
    }
    public function getEtag()
    {
        return $this->headers->get('ETag');
    }
    public function setEtag($etag = null, $weak = false)
    {
        if (null === $etag) {
            $this->headers->remove('Etag');
        } else {
            if (0 !== strpos($etag, '"')) {
                $etag = '"' . $etag . '"';
            }
            $this->headers->set('ETag', (true === $weak ? 'W/' : '') . $etag);
        }
        return $this;
    }
    public function setCache(array $options)
    {
        if ($diff = array_diff(array_keys($options), array('etag', 'last_modified', 'max_age', 's_maxage', 'private', 'public'))) {
            throw new \InvalidArgumentException(sprintf('Response does not support the following options: "%s".', implode('", "', array_values($diff))));
        }
        if (isset($options['etag'])) {
            $this->setEtag($options['etag']);
        }
        if (isset($options['last_modified'])) {
            $this->setLastModified($options['last_modified']);
        }
        if (isset($options['max_age'])) {
            $this->setMaxAge($options['max_age']);
        }
        if (isset($options['s_maxage'])) {
            $this->setSharedMaxAge($options['s_maxage']);
        }
        if (isset($options['public'])) {
            if ($options['public']) {
                $this->setPublic();
            } else {
                $this->setPrivate();
            }
        }
        if (isset($options['private'])) {
            if ($options['private']) {
                $this->setPrivate();
            } else {
                $this->setPublic();
            }
        }
        return $this;
    }
    public function setNotModified()
    {
        $this->setStatusCode(304);
        $this->setContent(null);
        foreach (array('Allow', 'Content-Encoding', 'Content-Language', 'Content-Length', 'Content-MD5', 'Content-Type', 'Last-Modified') as $header) {
            $this->headers->remove($header);
        }
        return $this;
    }
    public function hasVary()
    {
        return null !== $this->headers->get('Vary');
    }
    public function getVary()
    {
        if (!($vary = $this->headers->get('Vary', null, false))) {
            return array();
        }
        $ret = array();
        foreach ($vary as $item) {
            $ret = array_merge($ret, preg_split('/[\\s,]+/', $item));
        }
        return $ret;
    }
    public function setVary($headers, $replace = true)
    {
        $this->headers->set('Vary', $headers, $replace);
        return $this;
    }
    public function isNotModified(Request $request)
    {
        if (!$request->isMethodCacheable()) {
            return false;
        }
        $notModified = false;
        $lastModified = $this->headers->get('Last-Modified');
        $modifiedSince = $request->headers->get('If-Modified-Since');
        if ($etags = $request->getETags()) {
            $notModified = in_array($this->getEtag(), $etags) || in_array('*', $etags);
        }
        if ($modifiedSince && $lastModified) {
            $notModified = strtotime($modifiedSince) >= strtotime($lastModified) && (!$etags || $notModified);
        }
        if ($notModified) {
            $this->setNotModified();
        }
        return $notModified;
    }
    public function isInvalid()
    {
        return $this->statusCode < 100 || $this->statusCode >= 600;
    }
    public function isInformational()
    {
        return $this->statusCode >= 100 && $this->statusCode < 200;
    }
    public function isSuccessful()
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }
    public function isRedirection()
    {
        return $this->statusCode >= 300 && $this->statusCode < 400;
    }
    public function isClientError()
    {
        return $this->statusCode >= 400 && $this->statusCode < 500;
    }
    public function isServerError()
    {
        return $this->statusCode >= 500 && $this->statusCode < 600;
    }
    public function isOk()
    {
        return 200 === $this->statusCode;
    }
    public function isForbidden()
    {
        return 403 === $this->statusCode;
    }
    public function isNotFound()
    {
        return 404 === $this->statusCode;
    }
    public function isRedirect($location = null)
    {
        return in_array($this->statusCode, array(201, 301, 302, 303, 307, 308)) && (null === $location ?: $location == $this->headers->get('Location'));
    }
    public function isEmpty()
    {
        return in_array($this->statusCode, array(204, 304));
    }
    public static function closeOutputBuffers($targetLevel, $flush)
    {
        $status = ob_get_status(true);
        $level = count($status);
        $flags = defined('PHP_OUTPUT_HANDLER_REMOVABLE') ? PHP_OUTPUT_HANDLER_REMOVABLE | ($flush ? PHP_OUTPUT_HANDLER_FLUSHABLE : PHP_OUTPUT_HANDLER_CLEANABLE) : -1;
        while ($level-- > $targetLevel && ($s = $status[$level]) && (!isset($s['del']) ? !isset($s['flags']) || $flags === ($s['flags'] & $flags) : $s['del'])) {
            if ($flush) {
                ob_end_flush();
            } else {
                ob_end_clean();
            }
        }
    }
    protected function ensureIEOverSSLCompatibility(Request $request)
    {
        if (false !== stripos($this->headers->get('Content-Disposition'), 'attachment') && preg_match('/MSIE (.*?);/i', $request->server->get('HTTP_USER_AGENT'), $match) == 1 && true === $request->isSecure()) {
            if ((int) preg_replace('/(MSIE )(.*?);/', '$2', $match[0]) < 9) {
                $this->headers->remove('Cache-Control');
            }
        }
    }
}
}

namespace Symfony\Component\HttpFoundation {
class ResponseHeaderBag extends HeaderBag
{
    const COOKIES_FLAT = 'flat';
    const COOKIES_ARRAY = 'array';
    const DISPOSITION_ATTACHMENT = 'attachment';
    const DISPOSITION_INLINE = 'inline';
    protected $computedCacheControl = array();
    protected $cookies = array();
    protected $headerNames = array();
    public function __construct(array $headers = array())
    {
        parent::__construct($headers);
        if (!isset($this->headers['cache-control'])) {
            $this->set('Cache-Control', '');
        }
    }
    public function __toString()
    {
        $cookies = '';
        foreach ($this->getCookies() as $cookie) {
            $cookies .= 'Set-Cookie: ' . $cookie . "\r\n";
        }
        ksort($this->headerNames);
        return parent::__toString() . $cookies;
    }
    public function allPreserveCase()
    {
        return array_combine($this->headerNames, $this->headers);
    }
    public function replace(array $headers = array())
    {
        $this->headerNames = array();
        parent::replace($headers);
        if (!isset($this->headers['cache-control'])) {
            $this->set('Cache-Control', '');
        }
    }
    public function set($key, $values, $replace = true)
    {
        parent::set($key, $values, $replace);
        $uniqueKey = str_replace('_', '-', strtolower($key));
        $this->headerNames[$uniqueKey] = $key;
        if (in_array($uniqueKey, array('cache-control', 'etag', 'last-modified', 'expires'))) {
            $computed = $this->computeCacheControlValue();
            $this->headers['cache-control'] = array($computed);
            $this->headerNames['cache-control'] = 'Cache-Control';
            $this->computedCacheControl = $this->parseCacheControl($computed);
        }
    }
    public function remove($key)
    {
        parent::remove($key);
        $uniqueKey = str_replace('_', '-', strtolower($key));
        unset($this->headerNames[$uniqueKey]);
        if ('cache-control' === $uniqueKey) {
            $this->computedCacheControl = array();
        }
    }
    public function hasCacheControlDirective($key)
    {
        return array_key_exists($key, $this->computedCacheControl);
    }
    public function getCacheControlDirective($key)
    {
        return array_key_exists($key, $this->computedCacheControl) ? $this->computedCacheControl[$key] : null;
    }
    public function setCookie(Cookie $cookie)
    {
        $this->cookies[$cookie->getDomain()][$cookie->getPath()][$cookie->getName()] = $cookie;
    }
    public function removeCookie($name, $path = '/', $domain = null)
    {
        if (null === $path) {
            $path = '/';
        }
        unset($this->cookies[$domain][$path][$name]);
        if (empty($this->cookies[$domain][$path])) {
            unset($this->cookies[$domain][$path]);
            if (empty($this->cookies[$domain])) {
                unset($this->cookies[$domain]);
            }
        }
    }
    public function getCookies($format = self::COOKIES_FLAT)
    {
        if (!in_array($format, array(self::COOKIES_FLAT, self::COOKIES_ARRAY))) {
            throw new \InvalidArgumentException(sprintf('Format "%s" invalid (%s).', $format, implode(', ', array(self::COOKIES_FLAT, self::COOKIES_ARRAY))));
        }
        if (self::COOKIES_ARRAY === $format) {
            return $this->cookies;
        }
        $flattenedCookies = array();
        foreach ($this->cookies as $path) {
            foreach ($path as $cookies) {
                foreach ($cookies as $cookie) {
                    $flattenedCookies[] = $cookie;
                }
            }
        }
        return $flattenedCookies;
    }
    public function clearCookie($name, $path = '/', $domain = null, $secure = false, $httpOnly = true)
    {
        $this->setCookie(new Cookie($name, null, 1, $path, $domain, $secure, $httpOnly));
    }
    public function makeDisposition($disposition, $filename, $filenameFallback = '')
    {
        if (!in_array($disposition, array(self::DISPOSITION_ATTACHMENT, self::DISPOSITION_INLINE))) {
            throw new \InvalidArgumentException(sprintf('The disposition must be either "%s" or "%s".', self::DISPOSITION_ATTACHMENT, self::DISPOSITION_INLINE));
        }
        if ('' == $filenameFallback) {
            $filenameFallback = $filename;
        }
        if (!preg_match('/^[\\x20-\\x7e]*$/', $filenameFallback)) {
            throw new \InvalidArgumentException('The filename fallback must only contain ASCII characters.');
        }
        if (false !== strpos($filenameFallback, '%')) {
            throw new \InvalidArgumentException('The filename fallback cannot contain the "%" character.');
        }
        if (false !== strpos($filename, '/') || false !== strpos($filename, '\\') || false !== strpos($filenameFallback, '/') || false !== strpos($filenameFallback, '\\')) {
            throw new \InvalidArgumentException('The filename and the fallback cannot contain the "/" and "\\" characters.');
        }
        $output = sprintf('%s; filename="%s"', $disposition, str_replace('"', '\\"', $filenameFallback));
        if ($filename !== $filenameFallback) {
            $output .= sprintf("; filename*=utf-8''%s", rawurlencode($filename));
        }
        return $output;
    }
    protected function computeCacheControlValue()
    {
        if (!$this->cacheControl && !$this->has('ETag') && !$this->has('Last-Modified') && !$this->has('Expires')) {
            return 'no-cache';
        }
        if (!$this->cacheControl) {
            return 'private, must-revalidate';
        }
        $header = $this->getCacheControlHeader();
        if (isset($this->cacheControl['public']) || isset($this->cacheControl['private'])) {
            return $header;
        }
        if (!isset($this->cacheControl['s-maxage'])) {
            return $header . ', private';
        }
        return $header;
    }
}
}

namespace Symfony\Component\HttpFoundation {
class Cookie
{
    protected $name;
    protected $value;
    protected $domain;
    protected $expire;
    protected $path;
    protected $secure;
    protected $httpOnly;
    private $raw;
    public function __construct($name, $value = null, $expire = 0, $path = '/', $domain = null, $secure = false, $httpOnly = true, $raw = false)
    {
        if (preg_match("/[=,; \t\r\n\v\f]/", $name)) {
            throw new \InvalidArgumentException(sprintf('The cookie name "%s" contains invalid characters.', $name));
        }
        if (empty($name)) {
            throw new \InvalidArgumentException('The cookie name cannot be empty.');
        }
        if ($expire instanceof \DateTimeInterface) {
            $expire = $expire->format('U');
        } elseif (!is_numeric($expire)) {
            $expire = strtotime($expire);
            if (false === $expire || -1 === $expire) {
                throw new \InvalidArgumentException('The cookie expiration time is not valid.');
            }
        }
        $this->name = $name;
        $this->value = $value;
        $this->domain = $domain;
        $this->expire = $expire;
        $this->path = empty($path) ? '/' : $path;
        $this->secure = (bool) $secure;
        $this->httpOnly = (bool) $httpOnly;
        $this->raw = (bool) $raw;
    }
    public function __toString()
    {
        $str = urlencode($this->getName()) . '=';
        if ('' === (string) $this->getValue()) {
            $str .= 'deleted; expires=' . gmdate('D, d-M-Y H:i:s T', time() - 31536001);
        } else {
            $str .= urlencode($this->getValue());
            if ($this->getExpiresTime() !== 0) {
                $str .= '; expires=' . gmdate('D, d-M-Y H:i:s T', $this->getExpiresTime());
            }
        }
        if ($this->path) {
            $str .= '; path=' . $this->path;
        }
        if ($this->getDomain()) {
            $str .= '; domain=' . $this->getDomain();
        }
        if (true === $this->isSecure()) {
            $str .= '; secure';
        }
        if (true === $this->isHttpOnly()) {
            $str .= '; httponly';
        }
        return $str;
    }
    public function getName()
    {
        return $this->name;
    }
    public function getValue()
    {
        return $this->value;
    }
    public function getDomain()
    {
        return $this->domain;
    }
    public function getExpiresTime()
    {
        return $this->expire;
    }
    public function getPath()
    {
        return $this->path;
    }
    public function isSecure()
    {
        return $this->secure;
    }
    public function isHttpOnly()
    {
        return $this->httpOnly;
    }
    public function isCleared()
    {
        return $this->expire < time();
    }
    public function isRaw()
    {
        return $this->raw;
    }
}
}

namespace Illuminate\Support {
use Illuminate\Console\Events\ArtisanStarting;
abstract class ServiceProvider
{
    protected $app;
    protected $defer = false;
    protected static $publishes = [];
    protected static $publishGroups = [];
    public function __construct($app)
    {
        $this->app = $app;
    }
    protected function mergeConfigFrom($path, $key)
    {
        $config = $this->app['config']->get($key, []);
        $this->app['config']->set($key, array_merge(require $path, $config));
    }
    protected function loadViewsFrom($path, $namespace)
    {
        if (is_dir($appPath = $this->app->resourcePath() . '/views/vendor/' . $namespace)) {
            $this->app['view']->addNamespace($namespace, $appPath);
        }
        $this->app['view']->addNamespace($namespace, $path);
    }
    protected function loadTranslationsFrom($path, $namespace)
    {
        $this->app['translator']->addNamespace($namespace, $path);
    }
    protected function loadMigrationsFrom($paths)
    {
        $this->app->afterResolving('migrator', function ($migrator) use($paths) {
            foreach ((array) $paths as $path) {
                $migrator->path($path);
            }
        });
    }
    protected function publishes(array $paths, $group = null)
    {
        $class = static::class;
        if (!array_key_exists($class, static::$publishes)) {
            static::$publishes[$class] = [];
        }
        static::$publishes[$class] = array_merge(static::$publishes[$class], $paths);
        if ($group) {
            if (!array_key_exists($group, static::$publishGroups)) {
                static::$publishGroups[$group] = [];
            }
            static::$publishGroups[$group] = array_merge(static::$publishGroups[$group], $paths);
        }
    }
    public static function pathsToPublish($provider = null, $group = null)
    {
        if ($provider && $group) {
            if (empty(static::$publishes[$provider]) || empty(static::$publishGroups[$group])) {
                return [];
            }
            return array_intersect_key(static::$publishes[$provider], static::$publishGroups[$group]);
        }
        if ($group && array_key_exists($group, static::$publishGroups)) {
            return static::$publishGroups[$group];
        }
        if ($provider && array_key_exists($provider, static::$publishes)) {
            return static::$publishes[$provider];
        }
        if ($group || $provider) {
            return [];
        }
        $paths = [];
        foreach (static::$publishes as $class => $publish) {
            $paths = array_merge($paths, $publish);
        }
        return $paths;
    }
    public function commands($commands)
    {
        $commands = is_array($commands) ? $commands : func_get_args();
        $events = $this->app['events'];
        $events->listen(ArtisanStarting::class, function ($event) use($commands) {
            $event->artisan->resolveCommands($commands);
        });
    }
    public function provides()
    {
        return [];
    }
    public function when()
    {
        return [];
    }
    public function isDeferred()
    {
        return $this->defer;
    }
    public static function compiles()
    {
        return [];
    }
}
}

namespace Illuminate\Support {
class AggregateServiceProvider extends ServiceProvider
{
    protected $providers = [];
    protected $instances = [];
    public function register()
    {
        $this->instances = [];
        foreach ($this->providers as $provider) {
            $this->instances[] = $this->app->register($provider);
        }
    }
    public function provides()
    {
        $provides = [];
        foreach ($this->providers as $provider) {
            $instance = $this->app->resolveProviderClass($provider);
            $provides = array_merge($provides, $instance->provides());
        }
        return $provides;
    }
}
}

namespace Illuminate\Support\Facades {
use Mockery;
use RuntimeException;
use Mockery\MockInterface;
abstract class Facade
{
    protected static $app;
    protected static $resolvedInstance;
    public static function swap($instance)
    {
        static::$resolvedInstance[static::getFacadeAccessor()] = $instance;
        static::$app->instance(static::getFacadeAccessor(), $instance);
    }
    public static function spy()
    {
        $name = static::getFacadeAccessor();
        if (static::isMock()) {
            $mock = static::$resolvedInstance[$name];
        } else {
            $class = static::getMockableClass($name);
            $mock = $class ? Mockery::spy($class) : Mockery::spy();
            static::$resolvedInstance[$name] = $mock;
            if (isset(static::$app)) {
                static::$app->instance($name, $mock);
            }
        }
    }
    public static function shouldReceive()
    {
        $name = static::getFacadeAccessor();
        if (static::isMock()) {
            $mock = static::$resolvedInstance[$name];
        } else {
            $mock = static::createFreshMockInstance($name);
        }
        return call_user_func_array([$mock, 'shouldReceive'], func_get_args());
    }
    protected static function createFreshMockInstance($name)
    {
        static::$resolvedInstance[$name] = $mock = static::createMockByName($name);
        $mock->shouldAllowMockingProtectedMethods();
        if (isset(static::$app)) {
            static::$app->instance($name, $mock);
        }
        return $mock;
    }
    protected static function createMockByName($name)
    {
        $class = static::getMockableClass($name);
        return $class ? Mockery::mock($class) : Mockery::mock();
    }
    protected static function isMock()
    {
        $name = static::getFacadeAccessor();
        return isset(static::$resolvedInstance[$name]) && static::$resolvedInstance[$name] instanceof MockInterface;
    }
    protected static function getMockableClass()
    {
        if ($root = static::getFacadeRoot()) {
            return get_class($root);
        }
    }
    public static function getFacadeRoot()
    {
        return static::resolveFacadeInstance(static::getFacadeAccessor());
    }
    protected static function getFacadeAccessor()
    {
        throw new RuntimeException('Facade does not implement getFacadeAccessor method.');
    }
    protected static function resolveFacadeInstance($name)
    {
        if (is_object($name)) {
            return $name;
        }
        if (isset(static::$resolvedInstance[$name])) {
            return static::$resolvedInstance[$name];
        }
        return static::$resolvedInstance[$name] = static::$app[$name];
    }
    public static function clearResolvedInstance($name)
    {
        unset(static::$resolvedInstance[$name]);
    }
    public static function clearResolvedInstances()
    {
        static::$resolvedInstance = [];
    }
    public static function getFacadeApplication()
    {
        return static::$app;
    }
    public static function setFacadeApplication($app)
    {
        static::$app = $app;
    }
    public static function __callStatic($method, $args)
    {
        $instance = static::getFacadeRoot();
        if (!$instance) {
            throw new RuntimeException('A facade root has not been set.');
        }
        return $instance->{$method}(...$args);
    }
}
}

namespace Illuminate\Support\Traits {
use Closure;
use BadMethodCallException;
trait Macroable
{
    protected static $macros = [];
    public static function macro($name, callable $macro)
    {
        static::$macros[$name] = $macro;
    }
    public static function hasMacro($name)
    {
        return isset(static::$macros[$name]);
    }
    public static function __callStatic($method, $parameters)
    {
        if (!static::hasMacro($method)) {
            throw new BadMethodCallException("Method {$method} does not exist.");
        }
        if (static::$macros[$method] instanceof Closure) {
            return call_user_func_array(Closure::bind(static::$macros[$method], null, static::class), $parameters);
        }
        return call_user_func_array(static::$macros[$method], $parameters);
    }
    public function __call($method, $parameters)
    {
        if (!static::hasMacro($method)) {
            throw new BadMethodCallException("Method {$method} does not exist.");
        }
        if (static::$macros[$method] instanceof Closure) {
            return call_user_func_array(static::$macros[$method]->bindTo($this, static::class), $parameters);
        }
        return call_user_func_array(static::$macros[$method], $parameters);
    }
}
}

namespace Illuminate\Support {
use ArrayAccess;
use Illuminate\Support\Traits\Macroable;
class Arr
{
    use Macroable;
    public static function accessible($value)
    {
        return is_array($value) || $value instanceof ArrayAccess;
    }
    public static function add($array, $key, $value)
    {
        if (is_null(static::get($array, $key))) {
            static::set($array, $key, $value);
        }
        return $array;
    }
    public static function collapse($array)
    {
        $results = [];
        foreach ($array as $values) {
            if ($values instanceof Collection) {
                $values = $values->all();
            } elseif (!is_array($values)) {
                continue;
            }
            $results = array_merge($results, $values);
        }
        return $results;
    }
    public static function divide($array)
    {
        return [array_keys($array), array_values($array)];
    }
    public static function dot($array, $prepend = '')
    {
        $results = [];
        foreach ($array as $key => $value) {
            if (is_array($value) && !empty($value)) {
                $results = array_merge($results, static::dot($value, $prepend . $key . '.'));
            } else {
                $results[$prepend . $key] = $value;
            }
        }
        return $results;
    }
    public static function except($array, $keys)
    {
        static::forget($array, $keys);
        return $array;
    }
    public static function exists($array, $key)
    {
        if ($array instanceof ArrayAccess) {
            return $array->offsetExists($key);
        }
        return array_key_exists($key, $array);
    }
    public static function first($array, callable $callback = null, $default = null)
    {
        if (is_null($callback)) {
            if (empty($array)) {
                return value($default);
            }
            foreach ($array as $item) {
                return $item;
            }
        }
        foreach ($array as $key => $value) {
            if (call_user_func($callback, $value, $key)) {
                return $value;
            }
        }
        return value($default);
    }
    public static function last($array, callable $callback = null, $default = null)
    {
        if (is_null($callback)) {
            return empty($array) ? value($default) : end($array);
        }
        return static::first(array_reverse($array, true), $callback, $default);
    }
    public static function flatten($array, $depth = INF)
    {
        return array_reduce($array, function ($result, $item) use($depth) {
            $item = $item instanceof Collection ? $item->all() : $item;
            if (!is_array($item)) {
                return array_merge($result, [$item]);
            } elseif ($depth === 1) {
                return array_merge($result, array_values($item));
            } else {
                return array_merge($result, static::flatten($item, $depth - 1));
            }
        }, []);
    }
    public static function forget(&$array, $keys)
    {
        $original =& $array;
        $keys = (array) $keys;
        if (count($keys) === 0) {
            return;
        }
        foreach ($keys as $key) {
            if (static::exists($array, $key)) {
                unset($array[$key]);
                continue;
            }
            $parts = explode('.', $key);
            $array =& $original;
            while (count($parts) > 1) {
                $part = array_shift($parts);
                if (isset($array[$part]) && is_array($array[$part])) {
                    $array =& $array[$part];
                } else {
                    continue 2;
                }
            }
            unset($array[array_shift($parts)]);
        }
    }
    public static function get($array, $key, $default = null)
    {
        if (!static::accessible($array)) {
            return value($default);
        }
        if (is_null($key)) {
            return $array;
        }
        if (static::exists($array, $key)) {
            return $array[$key];
        }
        foreach (explode('.', $key) as $segment) {
            if (static::accessible($array) && static::exists($array, $segment)) {
                $array = $array[$segment];
            } else {
                return value($default);
            }
        }
        return $array;
    }
    public static function has($array, $keys)
    {
        if (is_null($keys)) {
            return false;
        }
        $keys = (array) $keys;
        if (!$array) {
            return false;
        }
        if ($keys === []) {
            return false;
        }
        foreach ($keys as $key) {
            $subKeyArray = $array;
            if (static::exists($array, $key)) {
                continue;
            }
            foreach (explode('.', $key) as $segment) {
                if (static::accessible($subKeyArray) && static::exists($subKeyArray, $segment)) {
                    $subKeyArray = $subKeyArray[$segment];
                } else {
                    return false;
                }
            }
        }
        return true;
    }
    public static function isAssoc(array $array)
    {
        $keys = array_keys($array);
        return array_keys($keys) !== $keys;
    }
    public static function only($array, $keys)
    {
        return array_intersect_key($array, array_flip((array) $keys));
    }
    public static function pluck($array, $value, $key = null)
    {
        $results = [];
        list($value, $key) = static::explodePluckParameters($value, $key);
        foreach ($array as $item) {
            $itemValue = data_get($item, $value);
            if (is_null($key)) {
                $results[] = $itemValue;
            } else {
                $itemKey = data_get($item, $key);
                $results[$itemKey] = $itemValue;
            }
        }
        return $results;
    }
    protected static function explodePluckParameters($value, $key)
    {
        $value = is_string($value) ? explode('.', $value) : $value;
        $key = is_null($key) || is_array($key) ? $key : explode('.', $key);
        return [$value, $key];
    }
    public static function prepend($array, $value, $key = null)
    {
        if (is_null($key)) {
            array_unshift($array, $value);
        } else {
            $array = [$key => $value] + $array;
        }
        return $array;
    }
    public static function pull(&$array, $key, $default = null)
    {
        $value = static::get($array, $key, $default);
        static::forget($array, $key);
        return $value;
    }
    public static function set(&$array, $key, $value)
    {
        if (is_null($key)) {
            return $array = $value;
        }
        $keys = explode('.', $key);
        while (count($keys) > 1) {
            $key = array_shift($keys);
            if (!isset($array[$key]) || !is_array($array[$key])) {
                $array[$key] = [];
            }
            $array =& $array[$key];
        }
        $array[array_shift($keys)] = $value;
        return $array;
    }
    public static function sort($array, $callback)
    {
        return Collection::make($array)->sortBy($callback)->all();
    }
    public static function sortRecursive($array)
    {
        foreach ($array as &$value) {
            if (is_array($value)) {
                $value = static::sortRecursive($value);
            }
        }
        if (static::isAssoc($array)) {
            ksort($array);
        } else {
            sort($array);
        }
        return $array;
    }
    public static function where($array, callable $callback)
    {
        return array_filter($array, $callback, ARRAY_FILTER_USE_BOTH);
    }
}
}

namespace Illuminate\Support {
use Illuminate\Support\Traits\Macroable;
class Str
{
    use Macroable;
    protected static $snakeCache = [];
    protected static $camelCache = [];
    protected static $studlyCache = [];
    public static function ascii($value)
    {
        foreach (static::charsArray() as $key => $val) {
            $value = str_replace($val, $key, $value);
        }
        return preg_replace('/[^\\x20-\\x7E]/u', '', $value);
    }
    public static function camel($value)
    {
        if (isset(static::$camelCache[$value])) {
            return static::$camelCache[$value];
        }
        return static::$camelCache[$value] = lcfirst(static::studly($value));
    }
    public static function contains($haystack, $needles)
    {
        foreach ((array) $needles as $needle) {
            if ($needle != '' && mb_strpos($haystack, $needle) !== false) {
                return true;
            }
        }
        return false;
    }
    public static function endsWith($haystack, $needles)
    {
        foreach ((array) $needles as $needle) {
            if (substr($haystack, -strlen($needle)) === (string) $needle) {
                return true;
            }
        }
        return false;
    }
    public static function finish($value, $cap)
    {
        $quoted = preg_quote($cap, '/');
        return preg_replace('/(?:' . $quoted . ')+$/u', '', $value) . $cap;
    }
    public static function is($pattern, $value)
    {
        if ($pattern == $value) {
            return true;
        }
        $pattern = preg_quote($pattern, '#');
        $pattern = str_replace('\\*', '.*', $pattern);
        return (bool) preg_match('#^' . $pattern . '\\z#u', $value);
    }
    public static function length($value)
    {
        return mb_strlen($value);
    }
    public static function limit($value, $limit = 100, $end = '...')
    {
        if (mb_strwidth($value, 'UTF-8') <= $limit) {
            return $value;
        }
        return rtrim(mb_strimwidth($value, 0, $limit, '', 'UTF-8')) . $end;
    }
    public static function lower($value)
    {
        return mb_strtolower($value, 'UTF-8');
    }
    public static function words($value, $words = 100, $end = '...')
    {
        preg_match('/^\\s*+(?:\\S++\\s*+){1,' . $words . '}/u', $value, $matches);
        if (!isset($matches[0]) || static::length($value) === static::length($matches[0])) {
            return $value;
        }
        return rtrim($matches[0]) . $end;
    }
    public static function parseCallback($callback, $default)
    {
        return static::contains($callback, '@') ? explode('@', $callback, 2) : [$callback, $default];
    }
    public static function plural($value, $count = 2)
    {
        return Pluralizer::plural($value, $count);
    }
    public static function random($length = 16)
    {
        $string = '';
        while (($len = strlen($string)) < $length) {
            $size = $length - $len;
            $bytes = random_bytes($size);
            $string .= substr(str_replace(['/', '+', '='], '', base64_encode($bytes)), 0, $size);
        }
        return $string;
    }
    public static function quickRandom($length = 16)
    {
        if (PHP_MAJOR_VERSION > 5) {
            return static::random($length);
        }
        $pool = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        return substr(str_shuffle(str_repeat($pool, $length)), 0, $length);
    }
    public static function replaceArray($search, array $replace, $subject)
    {
        foreach ($replace as $value) {
            $subject = static::replaceFirst($search, $value, $subject);
        }
        return $subject;
    }
    public static function replaceFirst($search, $replace, $subject)
    {
        $position = strpos($subject, $search);
        if ($position !== false) {
            return substr_replace($subject, $replace, $position, strlen($search));
        }
        return $subject;
    }
    public static function replaceLast($search, $replace, $subject)
    {
        $position = strrpos($subject, $search);
        if ($position !== false) {
            return substr_replace($subject, $replace, $position, strlen($search));
        }
        return $subject;
    }
    public static function upper($value)
    {
        return mb_strtoupper($value, 'UTF-8');
    }
    public static function title($value)
    {
        return mb_convert_case($value, MB_CASE_TITLE, 'UTF-8');
    }
    public static function singular($value)
    {
        return Pluralizer::singular($value);
    }
    public static function slug($title, $separator = '-')
    {
        $title = static::ascii($title);
        $flip = $separator == '-' ? '_' : '-';
        $title = preg_replace('![' . preg_quote($flip) . ']+!u', $separator, $title);
        $title = preg_replace('![^' . preg_quote($separator) . '\\pL\\pN\\s]+!u', '', mb_strtolower($title));
        $title = preg_replace('![' . preg_quote($separator) . '\\s]+!u', $separator, $title);
        return trim($title, $separator);
    }
    public static function snake($value, $delimiter = '_')
    {
        $key = $value;
        if (isset(static::$snakeCache[$key][$delimiter])) {
            return static::$snakeCache[$key][$delimiter];
        }
        if (!ctype_lower($value)) {
            $value = preg_replace('/\\s+/u', '', $value);
            $value = static::lower(preg_replace('/(.)(?=[A-Z])/u', '$1' . $delimiter, $value));
        }
        return static::$snakeCache[$key][$delimiter] = $value;
    }
    public static function startsWith($haystack, $needles)
    {
        foreach ((array) $needles as $needle) {
            if ($needle != '' && substr($haystack, 0, strlen($needle)) === (string) $needle) {
                return true;
            }
        }
        return false;
    }
    public static function studly($value)
    {
        $key = $value;
        if (isset(static::$studlyCache[$key])) {
            return static::$studlyCache[$key];
        }
        $value = ucwords(str_replace(['-', '_'], ' ', $value));
        return static::$studlyCache[$key] = str_replace(' ', '', $value);
    }
    public static function substr($string, $start, $length = null)
    {
        return mb_substr($string, $start, $length, 'UTF-8');
    }
    public static function ucfirst($string)
    {
        return static::upper(static::substr($string, 0, 1)) . static::substr($string, 1);
    }
    protected static function charsArray()
    {
        static $charsArray;
        if (isset($charsArray)) {
            return $charsArray;
        }
        return $charsArray = ['0' => ['°', '₀', '۰'], '1' => ['¹', '₁', '۱'], '2' => ['²', '₂', '۲'], '3' => ['³', '₃', '۳'], '4' => ['⁴', '₄', '۴', '٤'], '5' => ['⁵', '₅', '۵', '٥'], '6' => ['⁶', '₆', '۶', '٦'], '7' => ['⁷', '₇', '۷'], '8' => ['⁸', '₈', '۸'], '9' => ['⁹', '₉', '۹'], 'a' => ['à', 'á', 'ả', 'ã', 'ạ', 'ă', 'ắ', 'ằ', 'ẳ', 'ẵ', 'ặ', 'â', 'ấ', 'ầ', 'ẩ', 'ẫ', 'ậ', 'ā', 'ą', 'å', 'α', 'ά', 'ἀ', 'ἁ', 'ἂ', 'ἃ', 'ἄ', 'ἅ', 'ἆ', 'ἇ', 'ᾀ', 'ᾁ', 'ᾂ', 'ᾃ', 'ᾄ', 'ᾅ', 'ᾆ', 'ᾇ', 'ὰ', 'ά', 'ᾰ', 'ᾱ', 'ᾲ', 'ᾳ', 'ᾴ', 'ᾶ', 'ᾷ', 'а', 'أ', 'အ', 'ာ', 'ါ', 'ǻ', 'ǎ', 'ª', 'ა', 'अ', 'ا'], 'b' => ['б', 'β', 'Ъ', 'Ь', 'ب', 'ဗ', 'ბ'], 'c' => ['ç', 'ć', 'č', 'ĉ', 'ċ'], 'd' => ['ď', 'ð', 'đ', 'ƌ', 'ȡ', 'ɖ', 'ɗ', 'ᵭ', 'ᶁ', 'ᶑ', 'д', 'δ', 'د', 'ض', 'ဍ', 'ဒ', 'დ'], 'e' => ['é', 'è', 'ẻ', 'ẽ', 'ẹ', 'ê', 'ế', 'ề', 'ể', 'ễ', 'ệ', 'ë', 'ē', 'ę', 'ě', 'ĕ', 'ė', 'ε', 'έ', 'ἐ', 'ἑ', 'ἒ', 'ἓ', 'ἔ', 'ἕ', 'ὲ', 'έ', 'е', 'ё', 'э', 'є', 'ə', 'ဧ', 'ေ', 'ဲ', 'ე', 'ए', 'إ', 'ئ'], 'f' => ['ф', 'φ', 'ف', 'ƒ', 'ფ'], 'g' => ['ĝ', 'ğ', 'ġ', 'ģ', 'г', 'ґ', 'γ', 'ဂ', 'გ', 'گ'], 'h' => ['ĥ', 'ħ', 'η', 'ή', 'ح', 'ه', 'ဟ', 'ှ', 'ჰ'], 'i' => ['í', 'ì', 'ỉ', 'ĩ', 'ị', 'î', 'ï', 'ī', 'ĭ', 'į', 'ı', 'ι', 'ί', 'ϊ', 'ΐ', 'ἰ', 'ἱ', 'ἲ', 'ἳ', 'ἴ', 'ἵ', 'ἶ', 'ἷ', 'ὶ', 'ί', 'ῐ', 'ῑ', 'ῒ', 'ΐ', 'ῖ', 'ῗ', 'і', 'ї', 'и', 'ဣ', 'ိ', 'ီ', 'ည်', 'ǐ', 'ი', 'इ'], 'j' => ['ĵ', 'ј', 'Ј', 'ჯ', 'ج'], 'k' => ['ķ', 'ĸ', 'к', 'κ', 'Ķ', 'ق', 'ك', 'က', 'კ', 'ქ', 'ک'], 'l' => ['ł', 'ľ', 'ĺ', 'ļ', 'ŀ', 'л', 'λ', 'ل', 'လ', 'ლ'], 'm' => ['м', 'μ', 'م', 'မ', 'მ'], 'n' => ['ñ', 'ń', 'ň', 'ņ', 'ŉ', 'ŋ', 'ν', 'н', 'ن', 'န', 'ნ'], 'o' => ['ó', 'ò', 'ỏ', 'õ', 'ọ', 'ô', 'ố', 'ồ', 'ổ', 'ỗ', 'ộ', 'ơ', 'ớ', 'ờ', 'ở', 'ỡ', 'ợ', 'ø', 'ō', 'ő', 'ŏ', 'ο', 'ὀ', 'ὁ', 'ὂ', 'ὃ', 'ὄ', 'ὅ', 'ὸ', 'ό', 'о', 'و', 'θ', 'ို', 'ǒ', 'ǿ', 'º', 'ო', 'ओ'], 'p' => ['п', 'π', 'ပ', 'პ', 'پ'], 'q' => ['ყ'], 'r' => ['ŕ', 'ř', 'ŗ', 'р', 'ρ', 'ر', 'რ'], 's' => ['ś', 'š', 'ş', 'с', 'σ', 'ș', 'ς', 'س', 'ص', 'စ', 'ſ', 'ს'], 't' => ['ť', 'ţ', 'т', 'τ', 'ț', 'ت', 'ط', 'ဋ', 'တ', 'ŧ', 'თ', 'ტ'], 'u' => ['ú', 'ù', 'ủ', 'ũ', 'ụ', 'ư', 'ứ', 'ừ', 'ử', 'ữ', 'ự', 'û', 'ū', 'ů', 'ű', 'ŭ', 'ų', 'µ', 'у', 'ဉ', 'ု', 'ူ', 'ǔ', 'ǖ', 'ǘ', 'ǚ', 'ǜ', 'უ', 'उ'], 'v' => ['в', 'ვ', 'ϐ'], 'w' => ['ŵ', 'ω', 'ώ', 'ဝ', 'ွ'], 'x' => ['χ', 'ξ'], 'y' => ['ý', 'ỳ', 'ỷ', 'ỹ', 'ỵ', 'ÿ', 'ŷ', 'й', 'ы', 'υ', 'ϋ', 'ύ', 'ΰ', 'ي', 'ယ'], 'z' => ['ź', 'ž', 'ż', 'з', 'ζ', 'ز', 'ဇ', 'ზ'], 'aa' => ['ع', 'आ', 'آ'], 'ae' => ['ä', 'æ', 'ǽ'], 'ai' => ['ऐ'], 'at' => ['@'], 'ch' => ['ч', 'ჩ', 'ჭ', 'چ'], 'dj' => ['ђ', 'đ'], 'dz' => ['џ', 'ძ'], 'ei' => ['ऍ'], 'gh' => ['غ', 'ღ'], 'ii' => ['ई'], 'ij' => ['ĳ'], 'kh' => ['х', 'خ', 'ხ'], 'lj' => ['љ'], 'nj' => ['њ'], 'oe' => ['ö', 'œ', 'ؤ'], 'oi' => ['ऑ'], 'oii' => ['ऒ'], 'ps' => ['ψ'], 'sh' => ['ш', 'შ', 'ش'], 'shch' => ['щ'], 'ss' => ['ß'], 'sx' => ['ŝ'], 'th' => ['þ', 'ϑ', 'ث', 'ذ', 'ظ'], 'ts' => ['ц', 'ც', 'წ'], 'ue' => ['ü'], 'uu' => ['ऊ'], 'ya' => ['я'], 'yu' => ['ю'], 'zh' => ['ж', 'ჟ', 'ژ'], '(c)' => ['©'], 'A' => ['Á', 'À', 'Ả', 'Ã', 'Ạ', 'Ă', 'Ắ', 'Ằ', 'Ẳ', 'Ẵ', 'Ặ', 'Â', 'Ấ', 'Ầ', 'Ẩ', 'Ẫ', 'Ậ', 'Å', 'Ā', 'Ą', 'Α', 'Ά', 'Ἀ', 'Ἁ', 'Ἂ', 'Ἃ', 'Ἄ', 'Ἅ', 'Ἆ', 'Ἇ', 'ᾈ', 'ᾉ', 'ᾊ', 'ᾋ', 'ᾌ', 'ᾍ', 'ᾎ', 'ᾏ', 'Ᾰ', 'Ᾱ', 'Ὰ', 'Ά', 'ᾼ', 'А', 'Ǻ', 'Ǎ'], 'B' => ['Б', 'Β', 'ब'], 'C' => ['Ç', 'Ć', 'Č', 'Ĉ', 'Ċ'], 'D' => ['Ď', 'Ð', 'Đ', 'Ɖ', 'Ɗ', 'Ƌ', 'ᴅ', 'ᴆ', 'Д', 'Δ'], 'E' => ['É', 'È', 'Ẻ', 'Ẽ', 'Ẹ', 'Ê', 'Ế', 'Ề', 'Ể', 'Ễ', 'Ệ', 'Ë', 'Ē', 'Ę', 'Ě', 'Ĕ', 'Ė', 'Ε', 'Έ', 'Ἐ', 'Ἑ', 'Ἒ', 'Ἓ', 'Ἔ', 'Ἕ', 'Έ', 'Ὲ', 'Е', 'Ё', 'Э', 'Є', 'Ə'], 'F' => ['Ф', 'Φ'], 'G' => ['Ğ', 'Ġ', 'Ģ', 'Г', 'Ґ', 'Γ'], 'H' => ['Η', 'Ή', 'Ħ'], 'I' => ['Í', 'Ì', 'Ỉ', 'Ĩ', 'Ị', 'Î', 'Ï', 'Ī', 'Ĭ', 'Į', 'İ', 'Ι', 'Ί', 'Ϊ', 'Ἰ', 'Ἱ', 'Ἳ', 'Ἴ', 'Ἵ', 'Ἶ', 'Ἷ', 'Ῐ', 'Ῑ', 'Ὶ', 'Ί', 'И', 'І', 'Ї', 'Ǐ', 'ϒ'], 'K' => ['К', 'Κ'], 'L' => ['Ĺ', 'Ł', 'Л', 'Λ', 'Ļ', 'Ľ', 'Ŀ', 'ल'], 'M' => ['М', 'Μ'], 'N' => ['Ń', 'Ñ', 'Ň', 'Ņ', 'Ŋ', 'Н', 'Ν'], 'O' => ['Ó', 'Ò', 'Ỏ', 'Õ', 'Ọ', 'Ô', 'Ố', 'Ồ', 'Ổ', 'Ỗ', 'Ộ', 'Ơ', 'Ớ', 'Ờ', 'Ở', 'Ỡ', 'Ợ', 'Ø', 'Ō', 'Ő', 'Ŏ', 'Ο', 'Ό', 'Ὀ', 'Ὁ', 'Ὂ', 'Ὃ', 'Ὄ', 'Ὅ', 'Ὸ', 'Ό', 'О', 'Θ', 'Ө', 'Ǒ', 'Ǿ'], 'P' => ['П', 'Π'], 'R' => ['Ř', 'Ŕ', 'Р', 'Ρ', 'Ŗ'], 'S' => ['Ş', 'Ŝ', 'Ș', 'Š', 'Ś', 'С', 'Σ'], 'T' => ['Ť', 'Ţ', 'Ŧ', 'Ț', 'Т', 'Τ'], 'U' => ['Ú', 'Ù', 'Ủ', 'Ũ', 'Ụ', 'Ư', 'Ứ', 'Ừ', 'Ử', 'Ữ', 'Ự', 'Û', 'Ū', 'Ů', 'Ű', 'Ŭ', 'Ų', 'У', 'Ǔ', 'Ǖ', 'Ǘ', 'Ǚ', 'Ǜ'], 'V' => ['В'], 'W' => ['Ω', 'Ώ', 'Ŵ'], 'X' => ['Χ', 'Ξ'], 'Y' => ['Ý', 'Ỳ', 'Ỷ', 'Ỹ', 'Ỵ', 'Ÿ', 'Ῠ', 'Ῡ', 'Ὺ', 'Ύ', 'Ы', 'Й', 'Υ', 'Ϋ', 'Ŷ'], 'Z' => ['Ź', 'Ž', 'Ż', 'З', 'Ζ'], 'AE' => ['Ä', 'Æ', 'Ǽ'], 'CH' => ['Ч'], 'DJ' => ['Ђ'], 'DZ' => ['Џ'], 'GX' => ['Ĝ'], 'HX' => ['Ĥ'], 'IJ' => ['Ĳ'], 'JX' => ['Ĵ'], 'KH' => ['Х'], 'LJ' => ['Љ'], 'NJ' => ['Њ'], 'OE' => ['Ö', 'Œ'], 'PS' => ['Ψ'], 'SH' => ['Ш'], 'SHCH' => ['Щ'], 'SS' => ['ẞ'], 'TH' => ['Þ'], 'TS' => ['Ц'], 'UE' => ['Ü'], 'YA' => ['Я'], 'YU' => ['Ю'], 'ZH' => ['Ж'], ' ' => [" ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", " ", "　"]];
    }
}
}

namespace Illuminate\Support {
class NamespacedItemResolver
{
    protected $parsed = [];
    public function parseKey($key)
    {
        if (isset($this->parsed[$key])) {
            return $this->parsed[$key];
        }
        if (strpos($key, '::') === false) {
            $segments = explode('.', $key);
            $parsed = $this->parseBasicSegments($segments);
        } else {
            $parsed = $this->parseNamespacedSegments($key);
        }
        return $this->parsed[$key] = $parsed;
    }
    protected function parseBasicSegments(array $segments)
    {
        $group = $segments[0];
        if (count($segments) == 1) {
            return [null, $group, null];
        } else {
            $item = implode('.', array_slice($segments, 1));
            return [null, $group, $item];
        }
    }
    protected function parseNamespacedSegments($key)
    {
        list($namespace, $item) = explode('::', $key);
        $itemSegments = explode('.', $item);
        $groupAndItem = array_slice($this->parseBasicSegments($itemSegments), 1);
        return array_merge([$namespace], $groupAndItem);
    }
    public function setParsedKey($key, $parsed)
    {
        $this->parsed[$key] = $parsed;
    }
}
}

namespace Illuminate\Support\Facades {
class App extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'app';
    }
}
}

namespace Illuminate\Support\Facades {
class Route extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'router';
    }
}
}

namespace Illuminate\Support {
use Countable;
use Illuminate\Contracts\Support\MessageBag as MessageBagContract;
class ViewErrorBag implements Countable
{
    protected $bags = [];
    public function hasBag($key = 'default')
    {
        return isset($this->bags[$key]);
    }
    public function getBag($key)
    {
        return Arr::get($this->bags, $key) ?: new MessageBag();
    }
    public function getBags()
    {
        return $this->bags;
    }
    public function put($key, MessageBagContract $bag)
    {
        $this->bags[$key] = $bag;
        return $this;
    }
    public function count()
    {
        return $this->getBag('default')->count();
    }
    public function __call($method, $parameters)
    {
        return $this->getBag('default')->{$method}(...$parameters);
    }
    public function __get($key)
    {
        return $this->getBag($key);
    }
    public function __set($key, $value)
    {
        $this->put($key, $value);
    }
}
}

namespace Illuminate\Support {
use Countable;
use JsonSerializable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\MessageProvider;
use Illuminate\Contracts\Support\MessageBag as MessageBagContract;
class MessageBag implements Arrayable, Countable, Jsonable, JsonSerializable, MessageBagContract, MessageProvider
{
    protected $messages = [];
    protected $format = ':message';
    public function __construct(array $messages = [])
    {
        foreach ($messages as $key => $value) {
            $this->messages[$key] = (array) $value;
        }
    }
    public function keys()
    {
        return array_keys($this->messages);
    }
    public function add($key, $message)
    {
        if ($this->isUnique($key, $message)) {
            $this->messages[$key][] = $message;
        }
        return $this;
    }
    public function merge($messages)
    {
        if ($messages instanceof MessageProvider) {
            $messages = $messages->getMessageBag()->getMessages();
        }
        $this->messages = array_merge_recursive($this->messages, $messages);
        return $this;
    }
    protected function isUnique($key, $message)
    {
        $messages = (array) $this->messages;
        return !isset($messages[$key]) || !in_array($message, $messages[$key]);
    }
    public function has($key)
    {
        if (is_null($key)) {
            return $this->any();
        }
        $keys = is_array($key) ? $key : func_get_args();
        foreach ($keys as $key) {
            if ($this->first($key) === '') {
                return false;
            }
        }
        return true;
    }
    public function hasAny($keys = [])
    {
        foreach ($keys as $key) {
            if ($this->has($key)) {
                return true;
            }
        }
        return false;
    }
    public function first($key = null, $format = null)
    {
        $messages = is_null($key) ? $this->all($format) : $this->get($key, $format);
        return count($messages) > 0 ? $messages[0] : '';
    }
    public function get($key, $format = null)
    {
        if (array_key_exists($key, $this->messages)) {
            return $this->transform($this->messages[$key], $this->checkFormat($format), $key);
        }
        if (Str::contains($key, '*')) {
            return $this->getMessagesForWildcardKey($key, $format);
        }
        return [];
    }
    protected function getMessagesForWildcardKey($key, $format)
    {
        return collect($this->messages)->filter(function ($messages, $messageKey) use($key) {
            return Str::is($key, $messageKey);
        })->map(function ($messages, $messageKey) use($format) {
            return $this->transform($messages, $this->checkFormat($format), $messageKey);
        })->all();
    }
    public function all($format = null)
    {
        $format = $this->checkFormat($format);
        $all = [];
        foreach ($this->messages as $key => $messages) {
            $all = array_merge($all, $this->transform($messages, $format, $key));
        }
        return $all;
    }
    public function unique($format = null)
    {
        return array_unique($this->all($format));
    }
    protected function transform($messages, $format, $messageKey)
    {
        $messages = (array) $messages;
        $replace = [':message', ':key'];
        foreach ($messages as &$message) {
            $message = str_replace($replace, [$message, $messageKey], $format);
        }
        return $messages;
    }
    protected function checkFormat($format)
    {
        return $format ?: $this->format;
    }
    public function messages()
    {
        return $this->messages;
    }
    public function getMessages()
    {
        return $this->messages();
    }
    public function getMessageBag()
    {
        return $this;
    }
    public function getFormat()
    {
        return $this->format;
    }
    public function setFormat($format = ':message')
    {
        $this->format = $format;
        return $this;
    }
    public function isEmpty()
    {
        return !$this->any();
    }
    public function any()
    {
        return $this->count() > 0;
    }
    public function count()
    {
        return count($this->messages, COUNT_RECURSIVE) - count($this->messages);
    }
    public function toArray()
    {
        return $this->getMessages();
    }
    public function jsonSerialize()
    {
        return $this->toArray();
    }
    public function toJson($options = 0)
    {
        return json_encode($this->jsonSerialize(), $options);
    }
    public function __toString()
    {
        return $this->toJson();
    }
}
}

namespace Illuminate\Support\Facades {
class View extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'view';
    }
}
}

namespace Illuminate\Support {
use Closure;
use InvalidArgumentException;
abstract class Manager
{
    protected $app;
    protected $customCreators = [];
    protected $drivers = [];
    public function __construct($app)
    {
        $this->app = $app;
    }
    public abstract function getDefaultDriver();
    public function driver($driver = null)
    {
        $driver = $driver ?: $this->getDefaultDriver();
        if (!isset($this->drivers[$driver])) {
            $this->drivers[$driver] = $this->createDriver($driver);
        }
        return $this->drivers[$driver];
    }
    protected function createDriver($driver)
    {
        $method = 'create' . Str::studly($driver) . 'Driver';
        if (isset($this->customCreators[$driver])) {
            return $this->callCustomCreator($driver);
        } elseif (method_exists($this, $method)) {
            return $this->{$method}();
        }
        throw new InvalidArgumentException("Driver [{$driver}] not supported.");
    }
    protected function callCustomCreator($driver)
    {
        return $this->customCreators[$driver]($this->app);
    }
    public function extend($driver, Closure $callback)
    {
        $this->customCreators[$driver] = $callback;
        return $this;
    }
    public function getDrivers()
    {
        return $this->drivers;
    }
    public function __call($method, $parameters)
    {
        return $this->driver()->{$method}(...$parameters);
    }
}
}

namespace Illuminate\Support {
use Countable;
use ArrayAccess;
use Traversable;
use ArrayIterator;
use CachingIterator;
use JsonSerializable;
use IteratorAggregate;
use InvalidArgumentException;
use Illuminate\Support\Traits\Macroable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Arrayable;
class Collection implements ArrayAccess, Arrayable, Countable, IteratorAggregate, Jsonable, JsonSerializable
{
    use Macroable;
    protected $items = [];
    public function __construct($items = [])
    {
        $this->items = $this->getArrayableItems($items);
    }
    public static function make($items = [])
    {
        return new static($items);
    }
    public function all()
    {
        return $this->items;
    }
    public function avg($callback = null)
    {
        if ($count = $this->count()) {
            return $this->sum($callback) / $count;
        }
    }
    public function average($callback = null)
    {
        return $this->avg($callback);
    }
    public function median($key = null)
    {
        $count = $this->count();
        if ($count == 0) {
            return;
        }
        $values = with(isset($key) ? $this->pluck($key) : $this)->sort()->values();
        $middle = (int) ($count / 2);
        if ($count % 2) {
            return $values->get($middle);
        }
        return (new static([$values->get($middle - 1), $values->get($middle)]))->average();
    }
    public function mode($key = null)
    {
        $count = $this->count();
        if ($count == 0) {
            return;
        }
        $collection = isset($key) ? $this->pluck($key) : $this;
        $counts = new self();
        $collection->each(function ($value) use($counts) {
            $counts[$value] = isset($counts[$value]) ? $counts[$value] + 1 : 1;
        });
        $sorted = $counts->sort();
        $highestValue = $sorted->last();
        return $sorted->filter(function ($value) use($highestValue) {
            return $value == $highestValue;
        })->sort()->keys()->all();
    }
    public function collapse()
    {
        return new static(Arr::collapse($this->items));
    }
    public function contains($key, $value = null)
    {
        if (func_num_args() == 2) {
            return $this->contains(function ($item) use($key, $value) {
                return data_get($item, $key) == $value;
            });
        }
        if ($this->useAsCallable($key)) {
            return !is_null($this->first($key));
        }
        return in_array($key, $this->items);
    }
    public function containsStrict($key, $value = null)
    {
        if (func_num_args() == 2) {
            return $this->contains(function ($item) use($key, $value) {
                return data_get($item, $key) === $value;
            });
        }
        if ($this->useAsCallable($key)) {
            return !is_null($this->first($key));
        }
        return in_array($key, $this->items, true);
    }
    public function diff($items)
    {
        return new static(array_diff($this->items, $this->getArrayableItems($items)));
    }
    public function diffKeys($items)
    {
        return new static(array_diff_key($this->items, $this->getArrayableItems($items)));
    }
    public function each(callable $callback)
    {
        foreach ($this->items as $key => $item) {
            if ($callback($item, $key) === false) {
                break;
            }
        }
        return $this;
    }
    public function every($step, $offset = 0)
    {
        $new = [];
        $position = 0;
        foreach ($this->items as $item) {
            if ($position % $step === $offset) {
                $new[] = $item;
            }
            $position++;
        }
        return new static($new);
    }
    public function except($keys)
    {
        $keys = is_array($keys) ? $keys : func_get_args();
        return new static(Arr::except($this->items, $keys));
    }
    public function filter(callable $callback = null)
    {
        if ($callback) {
            return new static(Arr::where($this->items, $callback));
        }
        return new static(array_filter($this->items));
    }
    public function where($key, $operator, $value = null)
    {
        if (func_num_args() == 2) {
            $value = $operator;
            $operator = '=';
        }
        return $this->filter($this->operatorForWhere($key, $operator, $value));
    }
    protected function operatorForWhere($key, $operator, $value)
    {
        return function ($item) use($key, $operator, $value) {
            $retrieved = data_get($item, $key);
            switch ($operator) {
                default:
                case '=':
                case '==':
                    return $retrieved == $value;
                case '!=':
                case '<>':
                    return $retrieved != $value;
                case '<':
                    return $retrieved < $value;
                case '>':
                    return $retrieved > $value;
                case '<=':
                    return $retrieved <= $value;
                case '>=':
                    return $retrieved >= $value;
                case '===':
                    return $retrieved === $value;
                case '!==':
                    return $retrieved !== $value;
            }
        };
    }
    public function whereStrict($key, $value)
    {
        return $this->where($key, '===', $value);
    }
    public function whereIn($key, $values, $strict = false)
    {
        $values = $this->getArrayableItems($values);
        return $this->filter(function ($item) use($key, $values, $strict) {
            return in_array(data_get($item, $key), $values, $strict);
        });
    }
    public function whereInStrict($key, $values)
    {
        return $this->whereIn($key, $values, true);
    }
    public function first(callable $callback = null, $default = null)
    {
        return Arr::first($this->items, $callback, $default);
    }
    public function flatten($depth = INF)
    {
        return new static(Arr::flatten($this->items, $depth));
    }
    public function flip()
    {
        return new static(array_flip($this->items));
    }
    public function forget($keys)
    {
        foreach ((array) $keys as $key) {
            $this->offsetUnset($key);
        }
        return $this;
    }
    public function get($key, $default = null)
    {
        if ($this->offsetExists($key)) {
            return $this->items[$key];
        }
        return value($default);
    }
    public function groupBy($groupBy, $preserveKeys = false)
    {
        $groupBy = $this->valueRetriever($groupBy);
        $results = [];
        foreach ($this->items as $key => $value) {
            $groupKeys = $groupBy($value, $key);
            if (!is_array($groupKeys)) {
                $groupKeys = [$groupKeys];
            }
            foreach ($groupKeys as $groupKey) {
                if (!array_key_exists($groupKey, $results)) {
                    $results[$groupKey] = new static();
                }
                $results[$groupKey]->offsetSet($preserveKeys ? $key : null, $value);
            }
        }
        return new static($results);
    }
    public function keyBy($keyBy)
    {
        $keyBy = $this->valueRetriever($keyBy);
        $results = [];
        foreach ($this->items as $key => $item) {
            $results[$keyBy($item, $key)] = $item;
        }
        return new static($results);
    }
    public function has($key)
    {
        return $this->offsetExists($key);
    }
    public function implode($value, $glue = null)
    {
        $first = $this->first();
        if (is_array($first) || is_object($first)) {
            return implode($glue, $this->pluck($value)->all());
        }
        return implode($value, $this->items);
    }
    public function intersect($items)
    {
        return new static(array_intersect($this->items, $this->getArrayableItems($items)));
    }
    public function isEmpty()
    {
        return empty($this->items);
    }
    protected function useAsCallable($value)
    {
        return !is_string($value) && is_callable($value);
    }
    public function keys()
    {
        return new static(array_keys($this->items));
    }
    public function last(callable $callback = null, $default = null)
    {
        return Arr::last($this->items, $callback, $default);
    }
    public function pluck($value, $key = null)
    {
        return new static(Arr::pluck($this->items, $value, $key));
    }
    public function map(callable $callback)
    {
        $keys = array_keys($this->items);
        $items = array_map($callback, $this->items, $keys);
        return new static(array_combine($keys, $items));
    }
    public function mapWithKeys(callable $callback)
    {
        return $this->flatMap($callback);
    }
    public function flatMap(callable $callback)
    {
        return $this->map($callback)->collapse();
    }
    public function max($callback = null)
    {
        $callback = $this->valueRetriever($callback);
        return $this->reduce(function ($result, $item) use($callback) {
            $value = $callback($item);
            return is_null($result) || $value > $result ? $value : $result;
        });
    }
    public function merge($items)
    {
        return new static(array_merge($this->items, $this->getArrayableItems($items)));
    }
    public function combine($values)
    {
        return new static(array_combine($this->all(), $this->getArrayableItems($values)));
    }
    public function union($items)
    {
        return new static($this->items + $this->getArrayableItems($items));
    }
    public function min($callback = null)
    {
        $callback = $this->valueRetriever($callback);
        return $this->reduce(function ($result, $item) use($callback) {
            $value = $callback($item);
            return is_null($result) || $value < $result ? $value : $result;
        });
    }
    public function only($keys)
    {
        $keys = is_array($keys) ? $keys : func_get_args();
        return new static(Arr::only($this->items, $keys));
    }
    public function forPage($page, $perPage)
    {
        return $this->slice(($page - 1) * $perPage, $perPage);
    }
    public function pipe(callable $callback)
    {
        return $callback($this);
    }
    public function pop()
    {
        return array_pop($this->items);
    }
    public function prepend($value, $key = null)
    {
        $this->items = Arr::prepend($this->items, $value, $key);
        return $this;
    }
    public function push($value)
    {
        $this->offsetSet(null, $value);
        return $this;
    }
    public function pull($key, $default = null)
    {
        return Arr::pull($this->items, $key, $default);
    }
    public function put($key, $value)
    {
        $this->offsetSet($key, $value);
        return $this;
    }
    public function random($amount = 1)
    {
        if ($amount > ($count = $this->count())) {
            throw new InvalidArgumentException("You requested {$amount} items, but there are only {$count} items in the collection");
        }
        $keys = array_rand($this->items, $amount);
        if ($amount == 1) {
            return $this->items[$keys];
        }
        return new static(array_intersect_key($this->items, array_flip($keys)));
    }
    public function reduce(callable $callback, $initial = null)
    {
        return array_reduce($this->items, $callback, $initial);
    }
    public function reject($callback)
    {
        if ($this->useAsCallable($callback)) {
            return $this->filter(function ($value, $key) use($callback) {
                return !$callback($value, $key);
            });
        }
        return $this->filter(function ($item) use($callback) {
            return $item != $callback;
        });
    }
    public function reverse()
    {
        return new static(array_reverse($this->items, true));
    }
    public function search($value, $strict = false)
    {
        if (!$this->useAsCallable($value)) {
            return array_search($value, $this->items, $strict);
        }
        foreach ($this->items as $key => $item) {
            if (call_user_func($value, $item, $key)) {
                return $key;
            }
        }
        return false;
    }
    public function shift()
    {
        return array_shift($this->items);
    }
    public function shuffle($seed = null)
    {
        $items = $this->items;
        if (is_null($seed)) {
            shuffle($items);
        } else {
            srand($seed);
            usort($items, function () {
                return rand(-1, 1);
            });
        }
        return new static($items);
    }
    public function slice($offset, $length = null)
    {
        return new static(array_slice($this->items, $offset, $length, true));
    }
    public function split($numberOfGroups)
    {
        if ($this->isEmpty()) {
            return new static();
        }
        $groupSize = ceil($this->count() / $numberOfGroups);
        return $this->chunk($groupSize);
    }
    public function chunk($size)
    {
        $chunks = [];
        foreach (array_chunk($this->items, $size, true) as $chunk) {
            $chunks[] = new static($chunk);
        }
        return new static($chunks);
    }
    public function sort(callable $callback = null)
    {
        $items = $this->items;
        $callback ? uasort($items, $callback) : asort($items);
        return new static($items);
    }
    public function sortBy($callback, $options = SORT_REGULAR, $descending = false)
    {
        $results = [];
        $callback = $this->valueRetriever($callback);
        foreach ($this->items as $key => $value) {
            $results[$key] = $callback($value, $key);
        }
        $descending ? arsort($results, $options) : asort($results, $options);
        foreach (array_keys($results) as $key) {
            $results[$key] = $this->items[$key];
        }
        return new static($results);
    }
    public function sortByDesc($callback, $options = SORT_REGULAR)
    {
        return $this->sortBy($callback, $options, true);
    }
    public function splice($offset, $length = null, $replacement = [])
    {
        if (func_num_args() == 1) {
            return new static(array_splice($this->items, $offset));
        }
        return new static(array_splice($this->items, $offset, $length, $replacement));
    }
    public function sum($callback = null)
    {
        if (is_null($callback)) {
            return array_sum($this->items);
        }
        $callback = $this->valueRetriever($callback);
        return $this->reduce(function ($result, $item) use($callback) {
            return $result + $callback($item);
        }, 0);
    }
    public function take($limit)
    {
        if ($limit < 0) {
            return $this->slice($limit, abs($limit));
        }
        return $this->slice(0, $limit);
    }
    public function transform(callable $callback)
    {
        $this->items = $this->map($callback)->all();
        return $this;
    }
    public function unique($key = null, $strict = false)
    {
        if (is_null($key)) {
            return new static(array_unique($this->items, SORT_REGULAR));
        }
        $key = $this->valueRetriever($key);
        $exists = [];
        return $this->reject(function ($item) use($key, $strict, &$exists) {
            if (in_array($id = $key($item), $exists, $strict)) {
                return true;
            }
            $exists[] = $id;
        });
    }
    public function uniqueStrict($key = null)
    {
        return $this->unique($key, true);
    }
    public function values()
    {
        return new static(array_values($this->items));
    }
    protected function valueRetriever($value)
    {
        if ($this->useAsCallable($value)) {
            return $value;
        }
        return function ($item) use($value) {
            return data_get($item, $value);
        };
    }
    public function zip($items)
    {
        $arrayableItems = array_map(function ($items) {
            return $this->getArrayableItems($items);
        }, func_get_args());
        $params = array_merge([function () {
            return new static(func_get_args());
        }, $this->items], $arrayableItems);
        return new static(call_user_func_array('array_map', $params));
    }
    public function toArray()
    {
        return array_map(function ($value) {
            return $value instanceof Arrayable ? $value->toArray() : $value;
        }, $this->items);
    }
    public function jsonSerialize()
    {
        return array_map(function ($value) {
            if ($value instanceof JsonSerializable) {
                return $value->jsonSerialize();
            } elseif ($value instanceof Jsonable) {
                return json_decode($value->toJson(), true);
            } elseif ($value instanceof Arrayable) {
                return $value->toArray();
            } else {
                return $value;
            }
        }, $this->items);
    }
    public function toJson($options = 0)
    {
        return json_encode($this->jsonSerialize(), $options);
    }
    public function getIterator()
    {
        return new ArrayIterator($this->items);
    }
    public function getCachingIterator($flags = CachingIterator::CALL_TOSTRING)
    {
        return new CachingIterator($this->getIterator(), $flags);
    }
    public function count()
    {
        return count($this->items);
    }
    public function toBase()
    {
        return new self($this);
    }
    public function offsetExists($key)
    {
        return array_key_exists($key, $this->items);
    }
    public function offsetGet($key)
    {
        return $this->items[$key];
    }
    public function offsetSet($key, $value)
    {
        if (is_null($key)) {
            $this->items[] = $value;
        } else {
            $this->items[$key] = $value;
        }
    }
    public function offsetUnset($key)
    {
        unset($this->items[$key]);
    }
    public function __toString()
    {
        return $this->toJson();
    }
    protected function getArrayableItems($items)
    {
        if (is_array($items)) {
            return $items;
        } elseif ($items instanceof self) {
            return $items->all();
        } elseif ($items instanceof Arrayable) {
            return $items->toArray();
        } elseif ($items instanceof Jsonable) {
            return json_decode($items->toJson(), true);
        } elseif ($items instanceof JsonSerializable) {
            return $items->jsonSerialize();
        } elseif ($items instanceof Traversable) {
            return iterator_to_array($items);
        }
        return (array) $items;
    }
}
}

namespace Illuminate\Support\Facades {
class Log extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'log';
    }
}
}

namespace Illuminate\Events {
use Exception;
use ReflectionClass;
use Illuminate\Support\Str;
use Illuminate\Container\Container;
use Illuminate\Contracts\Broadcasting\ShouldBroadcast;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Contracts\Broadcasting\Factory as BroadcastFactory;
use Illuminate\Contracts\Container\Container as ContainerContract;
class Dispatcher implements DispatcherContract
{
    protected $container;
    protected $listeners = [];
    protected $wildcards = [];
    protected $sorted = [];
    protected $firing = [];
    protected $queueResolver;
    public function __construct(ContainerContract $container = null)
    {
        $this->container = $container ?: new Container();
    }
    public function listen($events, $listener, $priority = 0)
    {
        foreach ((array) $events as $event) {
            if (Str::contains($event, '*')) {
                $this->setupWildcardListen($event, $listener);
            } else {
                $this->listeners[$event][$priority][] = $this->makeListener($listener);
                unset($this->sorted[$event]);
            }
        }
    }
    protected function setupWildcardListen($event, $listener)
    {
        $this->wildcards[$event][] = $this->makeListener($listener);
    }
    public function hasListeners($eventName)
    {
        return isset($this->listeners[$eventName]) || isset($this->wildcards[$eventName]);
    }
    public function push($event, $payload = [])
    {
        $this->listen($event . '_pushed', function () use($event, $payload) {
            $this->fire($event, $payload);
        });
    }
    public function subscribe($subscriber)
    {
        $subscriber = $this->resolveSubscriber($subscriber);
        $subscriber->subscribe($this);
    }
    protected function resolveSubscriber($subscriber)
    {
        if (is_string($subscriber)) {
            return $this->container->make($subscriber);
        }
        return $subscriber;
    }
    public function until($event, $payload = [])
    {
        return $this->fire($event, $payload, true);
    }
    public function flush($event)
    {
        $this->fire($event . '_pushed');
    }
    public function firing()
    {
        return last($this->firing);
    }
    public function fire($event, $payload = [], $halt = false)
    {
        if (is_object($event)) {
            list($payload, $event) = [[$event], get_class($event)];
        }
        $responses = [];
        if (!is_array($payload)) {
            $payload = [$payload];
        }
        $this->firing[] = $event;
        if (isset($payload[0]) && $payload[0] instanceof ShouldBroadcast) {
            $this->broadcastEvent($payload[0]);
        }
        foreach ($this->getListeners($event) as $listener) {
            $response = call_user_func_array($listener, $payload);
            if (!is_null($response) && $halt) {
                array_pop($this->firing);
                return $response;
            }
            if ($response === false) {
                break;
            }
            $responses[] = $response;
        }
        array_pop($this->firing);
        return $halt ? null : $responses;
    }
    protected function broadcastEvent($event)
    {
        $this->container->make(BroadcastFactory::class)->queue($event);
    }
    public function getListeners($eventName)
    {
        $wildcards = $this->getWildcardListeners($eventName);
        if (!isset($this->sorted[$eventName])) {
            $this->sortListeners($eventName);
        }
        return array_merge($this->sorted[$eventName], $wildcards);
    }
    protected function getWildcardListeners($eventName)
    {
        $wildcards = [];
        foreach ($this->wildcards as $key => $listeners) {
            if (Str::is($key, $eventName)) {
                $wildcards = array_merge($wildcards, $listeners);
            }
        }
        return $wildcards;
    }
    protected function sortListeners($eventName)
    {
        $listeners = isset($this->listeners[$eventName]) ? $this->listeners[$eventName] : [];
        if (class_exists($eventName, false)) {
            foreach (class_implements($eventName) as $interface) {
                if (isset($this->listeners[$interface])) {
                    $listeners = array_merge_recursive($listeners, $this->listeners[$interface]);
                }
            }
        }
        if ($listeners) {
            krsort($listeners);
            $this->sorted[$eventName] = call_user_func_array('array_merge', $listeners);
        } else {
            $this->sorted[$eventName] = [];
        }
    }
    public function makeListener($listener)
    {
        return is_string($listener) ? $this->createClassListener($listener) : $listener;
    }
    public function createClassListener($listener)
    {
        $container = $this->container;
        return function () use($listener, $container) {
            return call_user_func_array($this->createClassCallable($listener, $container), func_get_args());
        };
    }
    protected function createClassCallable($listener, $container)
    {
        list($class, $method) = $this->parseClassCallable($listener);
        if ($this->handlerShouldBeQueued($class)) {
            return $this->createQueuedHandlerCallable($class, $method);
        } else {
            return [$container->make($class), $method];
        }
    }
    protected function parseClassCallable($listener)
    {
        $segments = explode('@', $listener);
        return [$segments[0], count($segments) == 2 ? $segments[1] : 'handle'];
    }
    protected function handlerShouldBeQueued($class)
    {
        try {
            return (new ReflectionClass($class))->implementsInterface('Illuminate\\Contracts\\Queue\\ShouldQueue');
        } catch (Exception $e) {
            return false;
        }
    }
    protected function createQueuedHandlerCallable($class, $method)
    {
        return function () use($class, $method) {
            $arguments = $this->cloneArgumentsForQueueing(func_get_args());
            if (method_exists($class, 'queue')) {
                $this->callQueueMethodOnHandler($class, $method, $arguments);
            } else {
                $this->resolveQueue()->push('Illuminate\\Events\\CallQueuedHandler@call', ['class' => $class, 'method' => $method, 'data' => serialize($arguments)]);
            }
        };
    }
    protected function cloneArgumentsForQueueing(array $arguments)
    {
        return array_map(function ($a) {
            return is_object($a) ? clone $a : $a;
        }, $arguments);
    }
    protected function callQueueMethodOnHandler($class, $method, $arguments)
    {
        $handler = (new ReflectionClass($class))->newInstanceWithoutConstructor();
        $handler->queue($this->resolveQueue(), 'Illuminate\\Events\\CallQueuedHandler@call', ['class' => $class, 'method' => $method, 'data' => serialize($arguments)]);
    }
    public function forget($event)
    {
        if (Str::contains($event, '*')) {
            unset($this->wildcards[$event]);
        } else {
            unset($this->listeners[$event], $this->sorted[$event]);
        }
    }
    public function forgetPushed()
    {
        foreach ($this->listeners as $key => $value) {
            if (Str::endsWith($key, '_pushed')) {
                $this->forget($key);
            }
        }
    }
    protected function resolveQueue()
    {
        return call_user_func($this->queueResolver);
    }
    public function setQueueResolver(callable $resolver)
    {
        $this->queueResolver = $resolver;
        return $this;
    }
}
}

namespace Illuminate\Events {
use Illuminate\Support\ServiceProvider;
class EventServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton('events', function ($app) {
            return (new Dispatcher($app))->setQueueResolver(function () use($app) {
                return $app->make('Illuminate\\Contracts\\Queue\\Factory');
            });
        });
    }
}
}

namespace Illuminate\Validation {
use Closure;
use DateTime;
use Countable;
use Exception;
use DateTimeZone;
use RuntimeException;
use DateTimeInterface;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use BadMethodCallException;
use InvalidArgumentException;
use Illuminate\Support\Fluent;
use Illuminate\Support\MessageBag;
use Illuminate\Contracts\Container\Container;
use Symfony\Component\HttpFoundation\File\File;
use Symfony\Component\Translation\TranslatorInterface;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Illuminate\Contracts\Validation\Validator as ValidatorContract;
class Validator implements ValidatorContract
{
    protected $translator;
    protected $presenceVerifier;
    protected $container;
    protected $failedRules = [];
    protected $messages;
    protected $data;
    protected $files = [];
    protected $initialRules;
    protected $rules;
    protected $implicitAttributes = [];
    protected $after = [];
    protected $customMessages = [];
    protected $fallbackMessages = [];
    protected $customAttributes = [];
    protected $customValues = [];
    protected $extensions = [];
    protected $replacers = [];
    protected $sizeRules = ['Size', 'Between', 'Min', 'Max'];
    protected $fileRules = ['File', 'Image', 'Mimes', 'Mimetypes', 'Min', 'Max', 'Size', 'Between', 'Dimensions'];
    protected $numericRules = ['Numeric', 'Integer'];
    protected $implicitRules = ['Required', 'Filled', 'RequiredWith', 'RequiredWithAll', 'RequiredWithout', 'RequiredWithoutAll', 'RequiredIf', 'RequiredUnless', 'Accepted', 'Present'];
    protected $dependentRules = ['RequiredWith', 'RequiredWithAll', 'RequiredWithout', 'RequiredWithoutAll', 'RequiredIf', 'RequiredUnless', 'Confirmed', 'Same', 'Different', 'Unique', 'Before', 'After'];
    public function __construct(TranslatorInterface $translator, array $data, array $rules, array $messages = [], array $customAttributes = [])
    {
        $this->initialRules = $rules;
        $this->translator = $translator;
        $this->customMessages = $messages;
        $this->customAttributes = $customAttributes;
        $this->data = $this->hydrateFiles($this->parseData($data));
        $this->setRules($rules);
    }
    public function parseData(array $data)
    {
        $newData = [];
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $value = $this->parseData($value);
            }
            if (Str::contains($key, '.')) {
                $newData[str_replace('.', '->', $key)] = $value;
            } else {
                $newData[$key] = $value;
            }
        }
        return $newData;
    }
    protected function hydrateFiles(array $data, $arrayKey = null)
    {
        if (is_null($arrayKey)) {
            $this->files = [];
        }
        foreach ($data as $key => $value) {
            $key = $arrayKey ? "{$arrayKey}.{$key}" : $key;
            if ($value instanceof File) {
                $this->files[$key] = $value;
                unset($data[$key]);
            } elseif (is_array($value)) {
                $this->hydrateFiles($value, $key);
            }
        }
        return $data;
    }
    protected function explodeRules($rules)
    {
        foreach ($rules as $key => $rule) {
            if (Str::contains($key, '*')) {
                $this->each($key, [$rule]);
                unset($rules[$key]);
            } else {
                $rules[$key] = is_string($rule) ? explode('|', $rule) : $rule;
            }
        }
        return $rules;
    }
    public function after($callback)
    {
        $this->after[] = function () use($callback) {
            return call_user_func_array($callback, [$this]);
        };
        return $this;
    }
    public function sometimes($attribute, $rules, callable $callback)
    {
        $payload = new Fluent($this->attributes());
        if (call_user_func($callback, $payload)) {
            foreach ((array) $attribute as $key) {
                if (Str::contains($key, '*')) {
                    $this->explodeRules([$key => $rules]);
                } else {
                    $this->mergeRules($key, $rules);
                }
            }
        }
    }
    public function each($attribute, $rules)
    {
        $data = Arr::dot($this->initializeAttributeOnData($attribute));
        $pattern = str_replace('\\*', '[^\\.]+', preg_quote($attribute));
        $data = array_merge($data, $this->extractValuesForWildcards($data, $attribute));
        foreach ($data as $key => $value) {
            if (Str::startsWith($key, $attribute) || (bool) preg_match('/^' . $pattern . '\\z/', $key)) {
                foreach ((array) $rules as $ruleKey => $ruleValue) {
                    if (!is_string($ruleKey) || Str::endsWith($key, $ruleKey)) {
                        $this->implicitAttributes[$attribute][] = $key;
                        $this->mergeRules($key, $ruleValue);
                    }
                }
            }
        }
    }
    protected function initializeAttributeOnData($attribute)
    {
        $explicitPath = $this->getLeadingExplicitAttributePath($attribute);
        $data = $this->extractDataFromPath($explicitPath);
        if (!Str::contains($attribute, '*') || Str::endsWith($attribute, '*')) {
            return $data;
        }
        return data_set($data, $attribute, null, true);
    }
    public function extractValuesForWildcards($data, $attribute)
    {
        $keys = [];
        $pattern = str_replace('\\*', '[^\\.]+', preg_quote($attribute));
        foreach ($data as $key => $value) {
            if ((bool) preg_match('/^' . $pattern . '/', $key, $matches)) {
                $keys[] = $matches[0];
            }
        }
        $keys = array_unique($keys);
        $data = [];
        foreach ($keys as $key) {
            $data[$key] = array_get($this->data, $key);
        }
        return $data;
    }
    public function mergeRules($attribute, $rules = [])
    {
        if (is_array($attribute)) {
            foreach ($attribute as $innerAttribute => $innerRules) {
                $this->mergeRulesForAttribute($innerAttribute, $innerRules);
            }
            return $this;
        }
        return $this->mergeRulesForAttribute($attribute, $rules);
    }
    protected function mergeRulesForAttribute($attribute, $rules)
    {
        $current = isset($this->rules[$attribute]) ? $this->rules[$attribute] : [];
        $merge = head($this->explodeRules([$rules]));
        $this->rules[$attribute] = array_merge($current, $merge);
        return $this;
    }
    public function passes()
    {
        $this->messages = new MessageBag();
        foreach ($this->rules as $attribute => $rules) {
            $attribute = str_replace('\\.', '->', $attribute);
            foreach ($rules as $rule) {
                $this->validateAttribute($attribute, $rule);
                if ($this->shouldStopValidating($attribute)) {
                    break;
                }
            }
        }
        foreach ($this->after as $after) {
            call_user_func($after);
        }
        return $this->messages->isEmpty();
    }
    public function fails()
    {
        return !$this->passes();
    }
    public function validate()
    {
        if ($this->fails()) {
            throw new ValidationException($this);
        }
    }
    protected function validateAttribute($attribute, $rule)
    {
        list($rule, $parameters) = $this->parseRule($rule);
        if ($rule == '') {
            return;
        }
        if (($keys = $this->getExplicitKeys($attribute)) && $this->dependsOnOtherFields($rule)) {
            $parameters = $this->replaceAsterisksInParameters($parameters, $keys);
        }
        $value = $this->getValue($attribute);
        if ($value instanceof UploadedFile && !$value->isValid() && $this->hasRule($attribute, array_merge($this->fileRules, $this->implicitRules))) {
            return $this->addFailure($attribute, 'uploaded', []);
        }
        $validatable = $this->isValidatable($rule, $attribute, $value);
        $method = "validate{$rule}";
        if ($validatable && !$this->{$method}($attribute, $value, $parameters, $this)) {
            $this->addFailure($attribute, $rule, $parameters);
        }
    }
    public function valid()
    {
        if (!$this->messages) {
            $this->passes();
        }
        return array_diff_key($this->data, $this->attributesThatHaveMessages());
    }
    public function invalid()
    {
        if (!$this->messages) {
            $this->passes();
        }
        return array_intersect_key($this->data, $this->attributesThatHaveMessages());
    }
    protected function attributesThatHaveMessages()
    {
        $results = [];
        foreach ($this->messages()->toArray() as $key => $message) {
            $results[] = explode('.', $key)[0];
        }
        return array_flip(array_unique($results));
    }
    protected function getValue($attribute)
    {
        if (!is_null($value = Arr::get($this->data, $attribute))) {
            return $value;
        } elseif (!is_null($value = Arr::get($this->files, $attribute))) {
            return $value;
        }
    }
    protected function isValidatable($rule, $attribute, $value)
    {
        return $this->presentOrRuleIsImplicit($rule, $attribute, $value) && $this->passesOptionalCheck($attribute) && $this->isNotNullIfMarkedAsNullable($attribute, $value) && $this->hasNotFailedPreviousRuleIfPresenceRule($rule, $attribute);
    }
    protected function presentOrRuleIsImplicit($rule, $attribute, $value)
    {
        if (is_string($value) && trim($value) === '') {
            return $this->isImplicit($rule);
        }
        return $this->validatePresent($attribute, $value) || $this->isImplicit($rule);
    }
    protected function passesOptionalCheck($attribute)
    {
        if ($this->hasRule($attribute, ['Sometimes'])) {
            return array_key_exists($attribute, Arr::dot($this->data)) || in_array($attribute, array_keys($this->data)) || array_key_exists($attribute, $this->files);
        }
        return true;
    }
    protected function isNotNullIfMarkedAsNullable($attribute, $value)
    {
        if (!$this->hasRule($attribute, ['Nullable'])) {
            return true;
        }
        return !is_null($value);
    }
    protected function isImplicit($rule)
    {
        return in_array($rule, $this->implicitRules);
    }
    protected function hasNotFailedPreviousRuleIfPresenceRule($rule, $attribute)
    {
        return in_array($rule, ['Unique', 'Exists']) ? !$this->messages->has($attribute) : true;
    }
    protected function addFailure($attribute, $rule, $parameters)
    {
        $this->addError($attribute, $rule, $parameters);
        $this->failedRules[$attribute][$rule] = $parameters;
    }
    protected function addError($attribute, $rule, $parameters)
    {
        $message = $this->getMessage($attribute, $rule);
        $message = $this->doReplacements($message, $attribute, $rule, $parameters);
        $this->messages->add($attribute, $message);
    }
    protected function validateSometimes()
    {
        return true;
    }
    protected function validateNullable()
    {
        return true;
    }
    protected function validateBail()
    {
        return true;
    }
    protected function shouldStopValidating($attribute)
    {
        if ($this->hasRule($attribute, ['Bail'])) {
            return $this->messages->has($attribute);
        }
        if (isset($this->failedRules[$attribute]) && in_array('uploaded', array_keys($this->failedRules[$attribute]))) {
            return true;
        }
        return $this->hasRule($attribute, $this->implicitRules) && isset($this->failedRules[$attribute]) && array_intersect(array_keys($this->failedRules[$attribute]), $this->implicitRules);
    }
    protected function validateRequired($attribute, $value)
    {
        if (is_null($value)) {
            return false;
        } elseif (is_string($value) && trim($value) === '') {
            return false;
        } elseif ((is_array($value) || $value instanceof Countable) && count($value) < 1) {
            return false;
        } elseif ($value instanceof File) {
            return (string) $value->getPath() != '';
        }
        return true;
    }
    protected function validatePresent($attribute, $value)
    {
        return Arr::has(array_merge($this->data, $this->files), $attribute);
    }
    protected function validateFilled($attribute, $value)
    {
        if (Arr::has(array_merge($this->data, $this->files), $attribute)) {
            return $this->validateRequired($attribute, $value);
        }
        return true;
    }
    protected function anyFailingRequired(array $attributes)
    {
        foreach ($attributes as $key) {
            if (!$this->validateRequired($key, $this->getValue($key))) {
                return true;
            }
        }
        return false;
    }
    protected function allFailingRequired(array $attributes)
    {
        foreach ($attributes as $key) {
            if ($this->validateRequired($key, $this->getValue($key))) {
                return false;
            }
        }
        return true;
    }
    protected function validateRequiredWith($attribute, $value, $parameters)
    {
        if (!$this->allFailingRequired($parameters)) {
            return $this->validateRequired($attribute, $value);
        }
        return true;
    }
    protected function validateRequiredWithAll($attribute, $value, $parameters)
    {
        if (!$this->anyFailingRequired($parameters)) {
            return $this->validateRequired($attribute, $value);
        }
        return true;
    }
    protected function validateRequiredWithout($attribute, $value, $parameters)
    {
        if ($this->anyFailingRequired($parameters)) {
            return $this->validateRequired($attribute, $value);
        }
        return true;
    }
    protected function validateRequiredWithoutAll($attribute, $value, $parameters)
    {
        if ($this->allFailingRequired($parameters)) {
            return $this->validateRequired($attribute, $value);
        }
        return true;
    }
    protected function validateRequiredIf($attribute, $value, $parameters)
    {
        $this->requireParameterCount(2, $parameters, 'required_if');
        $data = Arr::get($this->data, $parameters[0]);
        $values = array_slice($parameters, 1);
        if (is_bool($data)) {
            array_walk($values, function (&$value) {
                if ($value === 'true') {
                    $value = true;
                } elseif ($value === 'false') {
                    $value = false;
                }
            });
        }
        if (in_array($data, $values)) {
            return $this->validateRequired($attribute, $value);
        }
        return true;
    }
    protected function validateRequiredUnless($attribute, $value, $parameters)
    {
        $this->requireParameterCount(2, $parameters, 'required_unless');
        $data = Arr::get($this->data, $parameters[0]);
        $values = array_slice($parameters, 1);
        if (!in_array($data, $values)) {
            return $this->validateRequired($attribute, $value);
        }
        return true;
    }
    protected function getPresentCount($attributes)
    {
        $count = 0;
        foreach ($attributes as $key) {
            if (Arr::get($this->data, $key) || Arr::get($this->files, $key)) {
                $count++;
            }
        }
        return $count;
    }
    protected function validateInArray($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'in_array');
        $explicitPath = $this->getLeadingExplicitAttributePath($parameters[0]);
        $attributeData = $this->extractDataFromPath($explicitPath);
        $otherValues = Arr::where(Arr::dot($attributeData), function ($value, $key) use($parameters) {
            return Str::is($parameters[0], $key);
        });
        return in_array($value, $otherValues);
    }
    protected function validateConfirmed($attribute, $value)
    {
        return $this->validateSame($attribute, $value, [$attribute . '_confirmation']);
    }
    protected function validateSame($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'same');
        $other = Arr::get($this->data, $parameters[0]);
        return isset($other) && $value === $other;
    }
    protected function validateDifferent($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'different');
        $other = Arr::get($this->data, $parameters[0]);
        return isset($other) && $value !== $other;
    }
    protected function validateAccepted($attribute, $value)
    {
        $acceptable = ['yes', 'on', '1', 1, true, 'true'];
        return $this->validateRequired($attribute, $value) && in_array($value, $acceptable, true);
    }
    protected function validateArray($attribute, $value)
    {
        return is_array($value);
    }
    protected function validateBoolean($attribute, $value)
    {
        $acceptable = [true, false, 0, 1, '0', '1'];
        return in_array($value, $acceptable, true);
    }
    protected function validateInteger($attribute, $value)
    {
        return filter_var($value, FILTER_VALIDATE_INT) !== false;
    }
    protected function validateNumeric($attribute, $value)
    {
        return is_numeric($value);
    }
    protected function validateString($attribute, $value)
    {
        return is_string($value);
    }
    protected function validateJson($attribute, $value)
    {
        if (!is_scalar($value) && !method_exists($value, '__toString')) {
            return false;
        }
        json_decode($value);
        return json_last_error() === JSON_ERROR_NONE;
    }
    protected function validateDigits($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'digits');
        return !preg_match('/[^0-9]/', $value) && strlen((string) $value) == $parameters[0];
    }
    protected function validateDigitsBetween($attribute, $value, $parameters)
    {
        $this->requireParameterCount(2, $parameters, 'digits_between');
        $length = strlen((string) $value);
        return !preg_match('/[^0-9]/', $value) && $length >= $parameters[0] && $length <= $parameters[1];
    }
    protected function validateSize($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'size');
        return $this->getSize($attribute, $value) == $parameters[0];
    }
    protected function validateBetween($attribute, $value, $parameters)
    {
        $this->requireParameterCount(2, $parameters, 'between');
        $size = $this->getSize($attribute, $value);
        return $size >= $parameters[0] && $size <= $parameters[1];
    }
    protected function validateMin($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'min');
        return $this->getSize($attribute, $value) >= $parameters[0];
    }
    protected function validateMax($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'max');
        if ($value instanceof UploadedFile && !$value->isValid()) {
            return false;
        }
        return $this->getSize($attribute, $value) <= $parameters[0];
    }
    protected function getSize($attribute, $value)
    {
        $hasNumeric = $this->hasRule($attribute, $this->numericRules);
        if (is_numeric($value) && $hasNumeric) {
            return $value;
        } elseif (is_array($value)) {
            return count($value);
        } elseif ($value instanceof File) {
            return $value->getSize() / 1024;
        }
        return mb_strlen($value);
    }
    protected function validateIn($attribute, $value, $parameters)
    {
        if (is_array($value) && $this->hasRule($attribute, 'Array')) {
            foreach ($value as $element) {
                if (is_array($element)) {
                    return false;
                }
            }
            return count(array_diff($value, $parameters)) == 0;
        }
        return !is_array($value) && in_array((string) $value, $parameters);
    }
    protected function validateNotIn($attribute, $value, $parameters)
    {
        return !$this->validateIn($attribute, $value, $parameters);
    }
    protected function validateDistinct($attribute, $value, $parameters)
    {
        $attributeName = $this->getPrimaryAttribute($attribute);
        $explicitPath = $this->getLeadingExplicitAttributePath($attributeName);
        $attributeData = $this->extractDataFromPath($explicitPath);
        $data = Arr::where(Arr::dot($attributeData), function ($value, $key) use($attribute, $attributeName) {
            return $key != $attribute && Str::is($attributeName, $key);
        });
        return !in_array($value, array_values($data));
    }
    protected function validateUnique($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'unique');
        list($connection, $table) = $this->parseTable($parameters[0]);
        $column = isset($parameters[1]) ? $parameters[1] : $this->guessColumnForQuery($attribute);
        list($idColumn, $id) = [null, null];
        if (isset($parameters[2])) {
            list($idColumn, $id) = $this->getUniqueIds($parameters);
            if (preg_match('/\\[(.*)\\]/', $id, $matches)) {
                $id = $this->getValue($matches[1]);
            }
            if (strtolower($id) == 'null') {
                $id = null;
            }
            if (filter_var($id, FILTER_VALIDATE_INT) !== false) {
                $id = intval($id);
            }
        }
        $verifier = $this->getPresenceVerifier();
        $verifier->setConnection($connection);
        $extra = $this->getUniqueExtra($parameters);
        return $verifier->getCount($table, $column, $value, $id, $idColumn, $extra) == 0;
    }
    protected function parseTable($table)
    {
        return Str::contains($table, '.') ? explode('.', $table, 2) : [null, $table];
    }
    protected function getUniqueIds($parameters)
    {
        $idColumn = isset($parameters[3]) ? $parameters[3] : 'id';
        return [$idColumn, $parameters[2]];
    }
    protected function getUniqueExtra($parameters)
    {
        if (isset($parameters[4])) {
            return $this->getExtraConditions(array_slice($parameters, 4));
        }
        return [];
    }
    protected function validateExists($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'exists');
        list($connection, $table) = $this->parseTable($parameters[0]);
        $column = isset($parameters[1]) ? $parameters[1] : $this->guessColumnForQuery($attribute);
        $expected = is_array($value) ? count($value) : 1;
        return $this->getExistCount($connection, $table, $column, $value, $parameters) >= $expected;
    }
    protected function getExistCount($connection, $table, $column, $value, $parameters)
    {
        $verifier = $this->getPresenceVerifier();
        $verifier->setConnection($connection);
        $extra = $this->getExtraExistConditions($parameters);
        if (is_array($value)) {
            return $verifier->getMultiCount($table, $column, $value, $extra);
        }
        return $verifier->getCount($table, $column, $value, null, null, $extra);
    }
    protected function getExtraExistConditions(array $parameters)
    {
        return $this->getExtraConditions(array_values(array_slice($parameters, 2)));
    }
    protected function getExtraConditions(array $segments)
    {
        $extra = [];
        $count = count($segments);
        for ($i = 0; $i < $count; $i += 2) {
            $extra[$segments[$i]] = $segments[$i + 1];
        }
        return $extra;
    }
    public function guessColumnForQuery($attribute)
    {
        if (in_array($attribute, array_collapse($this->implicitAttributes)) && !is_numeric($last = last(explode('.', $attribute)))) {
            return $last;
        }
        return $attribute;
    }
    protected function validateIp($attribute, $value)
    {
        return filter_var($value, FILTER_VALIDATE_IP) !== false;
    }
    protected function validateEmail($attribute, $value)
    {
        return filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
    }
    protected function validateUrl($attribute, $value)
    {
        $pattern = '~^
            ((aaa|aaas|about|acap|acct|acr|adiumxtra|afp|afs|aim|apt|attachment|aw|barion|beshare|bitcoin|blob|bolo|callto|cap|chrome|chrome-extension|cid|coap|coaps|com-eventbrite-attendee|content|crid|cvs|data|dav|dict|dlna-playcontainer|dlna-playsingle|dns|dntp|dtn|dvb|ed2k|example|facetime|fax|feed|feedready|file|filesystem|finger|fish|ftp|geo|gg|git|gizmoproject|go|gopher|gtalk|h323|ham|hcp|http|https|iax|icap|icon|im|imap|info|iotdisco|ipn|ipp|ipps|irc|irc6|ircs|iris|iris.beep|iris.lwz|iris.xpc|iris.xpcs|itms|jabber|jar|jms|keyparc|lastfm|ldap|ldaps|magnet|mailserver|mailto|maps|market|message|mid|mms|modem|ms-help|ms-settings|ms-settings-airplanemode|ms-settings-bluetooth|ms-settings-camera|ms-settings-cellular|ms-settings-cloudstorage|ms-settings-emailandaccounts|ms-settings-language|ms-settings-location|ms-settings-lock|ms-settings-nfctransactions|ms-settings-notifications|ms-settings-power|ms-settings-privacy|ms-settings-proximity|ms-settings-screenrotation|ms-settings-wifi|ms-settings-workplace|msnim|msrp|msrps|mtqp|mumble|mupdate|mvn|news|nfs|ni|nih|nntp|notes|oid|opaquelocktoken|pack|palm|paparazzi|pkcs11|platform|pop|pres|prospero|proxy|psyc|query|redis|rediss|reload|res|resource|rmi|rsync|rtmfp|rtmp|rtsp|rtsps|rtspu|secondlife|service|session|sftp|sgn|shttp|sieve|sip|sips|skype|smb|sms|smtp|snews|snmp|soap.beep|soap.beeps|soldat|spotify|ssh|steam|stun|stuns|submit|svn|tag|teamspeak|tel|teliaeid|telnet|tftp|things|thismessage|tip|tn3270|turn|turns|tv|udp|unreal|urn|ut2004|vemmi|ventrilo|videotex|view-source|wais|webcal|ws|wss|wtai|wyciwyg|xcon|xcon-userid|xfire|xmlrpc\\.beep|xmlrpc.beeps|xmpp|xri|ymsgr|z39\\.50|z39\\.50r|z39\\.50s))://                                 # protocol
            (([\\pL\\pN-]+:)?([\\pL\\pN-]+)@)?          # basic auth
            (
                ([\\pL\\pN\\pS-\\.])+(\\.?([\\pL]|xn\\-\\-[\\pL\\pN-]+)+\\.?) # a domain name
                    |                                              # or
                \\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}                 # an IP address
                    |                                              # or
                \\[
                    (?:(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-f]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-f]{1,4})))?::(?:(?:(?:[0-9a-f]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,1}(?:(?:[0-9a-f]{1,4})))?::(?:(?:(?:[0-9a-f]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,2}(?:(?:[0-9a-f]{1,4})))?::(?:(?:(?:[0-9a-f]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,3}(?:(?:[0-9a-f]{1,4})))?::(?:(?:[0-9a-f]{1,4})):)(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,4}(?:(?:[0-9a-f]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-f]{1,4})):(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,5}(?:(?:[0-9a-f]{1,4})))?::)(?:(?:[0-9a-f]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-f]{1,4})):){0,6}(?:(?:[0-9a-f]{1,4})))?::))))
                \\]  # an IPv6 address
            )
            (:[0-9]+)?                              # a port (optional)
            (/?|/\\S+|\\?\\S*|\\#\\S*)                   # a /, nothing, a / with something, a query or a fragment
        $~ixu';
        return preg_match($pattern, $value) > 0;
    }
    protected function validateActiveUrl($attribute, $value)
    {
        if (!is_string($value)) {
            return false;
        }
        if ($url = parse_url($value, PHP_URL_HOST)) {
            return count(dns_get_record($url, DNS_A | DNS_AAAA)) > 0;
        }
        return false;
    }
    protected function validateFile($attribute, $value)
    {
        return $this->isAValidFileInstance($value);
    }
    protected function validateImage($attribute, $value)
    {
        return $this->validateMimes($attribute, $value, ['jpeg', 'png', 'gif', 'bmp', 'svg']);
    }
    protected function validateDimensions($attribute, $value, $parameters)
    {
        if (!$this->isAValidFileInstance($value) || !($sizeDetails = getimagesize($value->getRealPath()))) {
            return false;
        }
        $this->requireParameterCount(1, $parameters, 'dimensions');
        list($width, $height) = $sizeDetails;
        $parameters = $this->parseNamedParameters($parameters);
        if (isset($parameters['width']) && $parameters['width'] != $width || isset($parameters['min_width']) && $parameters['min_width'] > $width || isset($parameters['max_width']) && $parameters['max_width'] < $width || isset($parameters['height']) && $parameters['height'] != $height || isset($parameters['min_height']) && $parameters['min_height'] > $height || isset($parameters['max_height']) && $parameters['max_height'] < $height) {
            return false;
        }
        if (isset($parameters['ratio'])) {
            list($numerator, $denominator) = array_replace([1, 1], array_filter(sscanf($parameters['ratio'], '%f/%d')));
            return $numerator / $denominator == $width / $height;
        }
        return true;
    }
    protected function validateMimes($attribute, $value, $parameters)
    {
        if (!$this->isAValidFileInstance($value)) {
            return false;
        }
        return $value->getPath() != '' && in_array($value->guessExtension(), $parameters);
    }
    protected function validateMimetypes($attribute, $value, $parameters)
    {
        if (!$this->isAValidFileInstance($value)) {
            return false;
        }
        return $value->getPath() != '' && in_array($value->getMimeType(), $parameters);
    }
    public function isAValidFileInstance($value)
    {
        if ($value instanceof UploadedFile && !$value->isValid()) {
            return false;
        }
        return $value instanceof File;
    }
    protected function validateAlpha($attribute, $value)
    {
        return is_string($value) && preg_match('/^[\\pL\\pM]+$/u', $value);
    }
    protected function validateAlphaNum($attribute, $value)
    {
        if (!is_string($value) && !is_numeric($value)) {
            return false;
        }
        return preg_match('/^[\\pL\\pM\\pN]+$/u', $value) > 0;
    }
    protected function validateAlphaDash($attribute, $value)
    {
        if (!is_string($value) && !is_numeric($value)) {
            return false;
        }
        return preg_match('/^[\\pL\\pM\\pN_-]+$/u', $value) > 0;
    }
    protected function validateRegex($attribute, $value, $parameters)
    {
        if (!is_string($value) && !is_numeric($value)) {
            return false;
        }
        $this->requireParameterCount(1, $parameters, 'regex');
        return preg_match($parameters[0], $value) > 0;
    }
    protected function validateDate($attribute, $value)
    {
        if ($value instanceof DateTime) {
            return true;
        }
        if (!is_string($value) && !is_numeric($value) || strtotime($value) === false) {
            return false;
        }
        $date = date_parse($value);
        return checkdate($date['month'], $date['day'], $date['year']);
    }
    protected function validateDateFormat($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'date_format');
        if (!is_string($value) && !is_numeric($value)) {
            return false;
        }
        $parsed = date_parse_from_format($parameters[0], $value);
        return $parsed['error_count'] === 0 && $parsed['warning_count'] === 0;
    }
    protected function validateBefore($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'before');
        if (!is_string($value) && !is_numeric($value) && !$value instanceof DateTimeInterface) {
            return false;
        }
        if ($format = $this->getDateFormat($attribute)) {
            return $this->validateBeforeWithFormat($format, $value, $parameters);
        }
        if (!($date = $this->getDateTimestamp($parameters[0]))) {
            $date = $this->getDateTimestamp($this->getValue($parameters[0]));
        }
        return $this->getDateTimestamp($value) < $date;
    }
    protected function validateBeforeWithFormat($format, $value, $parameters)
    {
        $param = $this->getValue($parameters[0]) ?: $parameters[0];
        return $this->checkDateTimeOrder($format, $value, $param);
    }
    protected function validateAfter($attribute, $value, $parameters)
    {
        $this->requireParameterCount(1, $parameters, 'after');
        if (!is_string($value) && !is_numeric($value) && !$value instanceof DateTimeInterface) {
            return false;
        }
        if ($format = $this->getDateFormat($attribute)) {
            return $this->validateAfterWithFormat($format, $value, $parameters);
        }
        if (!($date = $this->getDateTimestamp($parameters[0]))) {
            $date = $this->getDateTimestamp($this->getValue($parameters[0]));
        }
        return $this->getDateTimestamp($value) > $date;
    }
    protected function validateAfterWithFormat($format, $value, $parameters)
    {
        $param = $this->getValue($parameters[0]) ?: $parameters[0];
        return $this->checkDateTimeOrder($format, $param, $value);
    }
    protected function checkDateTimeOrder($format, $before, $after)
    {
        $before = $this->getDateTimeWithOptionalFormat($format, $before);
        $after = $this->getDateTimeWithOptionalFormat($format, $after);
        return $before && $after && $after > $before;
    }
    protected function getDateTimeWithOptionalFormat($format, $value)
    {
        $date = DateTime::createFromFormat($format, $value);
        if ($date) {
            return $date;
        }
        try {
            return new DateTime($value);
        } catch (Exception $e) {
        }
    }
    protected function validateTimezone($attribute, $value)
    {
        try {
            new DateTimeZone($value);
        } catch (Exception $e) {
            return false;
        }
        return true;
    }
    protected function getDateFormat($attribute)
    {
        if ($result = $this->getRule($attribute, 'DateFormat')) {
            return $result[1][0];
        }
    }
    protected function getDateTimestamp($value)
    {
        return $value instanceof DateTimeInterface ? $value->getTimestamp() : strtotime($value);
    }
    protected function getMessage($attribute, $rule)
    {
        $lowerRule = Str::snake($rule);
        $inlineMessage = $this->getInlineMessage($attribute, $lowerRule);
        if (!is_null($inlineMessage)) {
            return $inlineMessage;
        }
        $customKey = "validation.custom.{$attribute}.{$lowerRule}";
        $customMessage = $this->getCustomMessageFromTranslator($customKey);
        if ($customMessage !== $customKey) {
            return $customMessage;
        } elseif (in_array($rule, $this->sizeRules)) {
            return $this->getSizeMessage($attribute, $rule);
        }
        $key = "validation.{$lowerRule}";
        if ($key != ($value = $this->translator->trans($key))) {
            return $value;
        }
        return $this->getInlineMessage($attribute, $lowerRule, $this->fallbackMessages) ?: $key;
    }
    protected function getInlineMessage($attribute, $lowerRule, $source = null)
    {
        $source = $source ?: $this->customMessages;
        $keys = ["{$attribute}.{$lowerRule}", $lowerRule];
        foreach ($keys as $key) {
            foreach (array_keys($source) as $sourceKey) {
                if (Str::is($sourceKey, $key)) {
                    return $source[$sourceKey];
                }
            }
        }
    }
    protected function getCustomMessageFromTranslator($customKey)
    {
        if (($message = $this->translator->trans($customKey)) !== $customKey) {
            return $message;
        }
        $shortKey = preg_replace('/^validation\\.custom\\./', '', $customKey);
        $customMessages = Arr::dot((array) $this->translator->trans('validation.custom'));
        foreach ($customMessages as $key => $message) {
            if ($shortKey === $key || Str::contains($key, ['*']) && Str::is($key, $shortKey)) {
                return $message;
            }
        }
        return $customKey;
    }
    protected function getSizeMessage($attribute, $rule)
    {
        $lowerRule = Str::snake($rule);
        $type = $this->getAttributeType($attribute);
        $key = "validation.{$lowerRule}.{$type}";
        return $this->translator->trans($key);
    }
    protected function getAttributeType($attribute)
    {
        if ($this->hasRule($attribute, $this->numericRules)) {
            return 'numeric';
        } elseif ($this->hasRule($attribute, ['Array'])) {
            return 'array';
        } elseif (array_key_exists($attribute, $this->files)) {
            return 'file';
        }
        return 'string';
    }
    protected function doReplacements($message, $attribute, $rule, $parameters)
    {
        $value = $this->getAttribute($attribute);
        $message = str_replace([':attribute', ':ATTRIBUTE', ':Attribute'], [$value, Str::upper($value), Str::ucfirst($value)], $message);
        if (isset($this->replacers[Str::snake($rule)])) {
            $message = $this->callReplacer($message, $attribute, Str::snake($rule), $parameters);
        } elseif (method_exists($this, $replacer = "replace{$rule}")) {
            $message = $this->{$replacer}($message, $attribute, $rule, $parameters);
        }
        return $message;
    }
    protected function getAttributeList(array $values)
    {
        $attributes = [];
        foreach ($values as $key => $value) {
            $attributes[$key] = $this->getAttribute($value);
        }
        return $attributes;
    }
    protected function getAttribute($attribute)
    {
        $primaryAttribute = $this->getPrimaryAttribute($attribute);
        $expectedAttributes = $attribute != $primaryAttribute ? [$attribute, $primaryAttribute] : [$attribute];
        foreach ($expectedAttributes as $expectedAttributeName) {
            if (isset($this->customAttributes[$expectedAttributeName])) {
                return $this->customAttributes[$expectedAttributeName];
            }
            $line = Arr::get($this->translator->get('validation.attributes'), $expectedAttributeName);
            if ($line) {
                return $line;
            }
        }
        if (isset($this->implicitAttributes[$primaryAttribute])) {
            return $attribute;
        }
        return str_replace('_', ' ', Str::snake($attribute));
    }
    protected function getPrimaryAttribute($attribute)
    {
        foreach ($this->implicitAttributes as $unparsed => $parsed) {
            if (in_array($attribute, $parsed)) {
                return $unparsed;
            }
        }
        return $attribute;
    }
    public function getDisplayableValue($attribute, $value)
    {
        if (isset($this->customValues[$attribute][$value])) {
            return $this->customValues[$attribute][$value];
        }
        $key = "validation.values.{$attribute}.{$value}";
        if (($line = $this->translator->trans($key)) !== $key) {
            return $line;
        }
        return $value;
    }
    protected function replaceBetween($message, $attribute, $rule, $parameters)
    {
        return str_replace([':min', ':max'], $parameters, $message);
    }
    protected function replaceDateFormat($message, $attribute, $rule, $parameters)
    {
        return str_replace(':format', $parameters[0], $message);
    }
    protected function replaceDifferent($message, $attribute, $rule, $parameters)
    {
        return $this->replaceSame($message, $attribute, $rule, $parameters);
    }
    protected function replaceDigits($message, $attribute, $rule, $parameters)
    {
        return str_replace(':digits', $parameters[0], $message);
    }
    protected function replaceDigitsBetween($message, $attribute, $rule, $parameters)
    {
        return $this->replaceBetween($message, $attribute, $rule, $parameters);
    }
    protected function replaceMin($message, $attribute, $rule, $parameters)
    {
        return str_replace(':min', $parameters[0], $message);
    }
    protected function replaceMax($message, $attribute, $rule, $parameters)
    {
        return str_replace(':max', $parameters[0], $message);
    }
    protected function replaceIn($message, $attribute, $rule, $parameters)
    {
        foreach ($parameters as &$parameter) {
            $parameter = $this->getDisplayableValue($attribute, $parameter);
        }
        return str_replace(':values', implode(', ', $parameters), $message);
    }
    protected function replaceNotIn($message, $attribute, $rule, $parameters)
    {
        return $this->replaceIn($message, $attribute, $rule, $parameters);
    }
    protected function replaceInArray($message, $attribute, $rule, $parameters)
    {
        return str_replace(':other', $this->getAttribute($parameters[0]), $message);
    }
    protected function replaceMimetypes($message, $attribute, $rule, $parameters)
    {
        return str_replace(':values', implode(', ', $parameters), $message);
    }
    protected function replaceMimes($message, $attribute, $rule, $parameters)
    {
        return str_replace(':values', implode(', ', $parameters), $message);
    }
    protected function replaceRequiredWith($message, $attribute, $rule, $parameters)
    {
        $parameters = $this->getAttributeList($parameters);
        return str_replace(':values', implode(' / ', $parameters), $message);
    }
    protected function replaceRequiredWithAll($message, $attribute, $rule, $parameters)
    {
        return $this->replaceRequiredWith($message, $attribute, $rule, $parameters);
    }
    protected function replaceRequiredWithout($message, $attribute, $rule, $parameters)
    {
        return $this->replaceRequiredWith($message, $attribute, $rule, $parameters);
    }
    protected function replaceRequiredWithoutAll($message, $attribute, $rule, $parameters)
    {
        return $this->replaceRequiredWith($message, $attribute, $rule, $parameters);
    }
    protected function replaceSize($message, $attribute, $rule, $parameters)
    {
        return str_replace(':size', $parameters[0], $message);
    }
    protected function replaceRequiredIf($message, $attribute, $rule, $parameters)
    {
        $parameters[1] = $this->getDisplayableValue($parameters[0], Arr::get($this->data, $parameters[0]));
        $parameters[0] = $this->getAttribute($parameters[0]);
        return str_replace([':other', ':value'], $parameters, $message);
    }
    protected function replaceRequiredUnless($message, $attribute, $rule, $parameters)
    {
        $other = $this->getAttribute(array_shift($parameters));
        return str_replace([':other', ':values'], [$other, implode(', ', $parameters)], $message);
    }
    protected function replaceSame($message, $attribute, $rule, $parameters)
    {
        return str_replace(':other', $this->getAttribute($parameters[0]), $message);
    }
    protected function replaceBefore($message, $attribute, $rule, $parameters)
    {
        if (!strtotime($parameters[0])) {
            return str_replace(':date', $this->getAttribute($parameters[0]), $message);
        }
        return str_replace(':date', $parameters[0], $message);
    }
    protected function replaceAfter($message, $attribute, $rule, $parameters)
    {
        return $this->replaceBefore($message, $attribute, $rule, $parameters);
    }
    public function attributes()
    {
        return array_merge($this->data, $this->files);
    }
    public function hasAttribute($attribute)
    {
        return Arr::has($this->attributes(), $attribute);
    }
    public function hasRule($attribute, $rules)
    {
        return !is_null($this->getRule($attribute, $rules));
    }
    protected function getRule($attribute, $rules)
    {
        if (!array_key_exists($attribute, $this->rules)) {
            return;
        }
        $rules = (array) $rules;
        foreach ($this->rules[$attribute] as $rule) {
            list($rule, $parameters) = $this->parseRule($rule);
            if (in_array($rule, $rules)) {
                return [$rule, $parameters];
            }
        }
    }
    protected function parseRule($rules)
    {
        if (is_array($rules)) {
            $rules = $this->parseArrayRule($rules);
        } else {
            $rules = $this->parseStringRule($rules);
        }
        $rules[0] = $this->normalizeRule($rules[0]);
        return $rules;
    }
    protected function parseArrayRule(array $rules)
    {
        return [Str::studly(trim(Arr::get($rules, 0))), array_slice($rules, 1)];
    }
    protected function parseStringRule($rules)
    {
        $parameters = [];
        if (strpos($rules, ':') !== false) {
            list($rules, $parameter) = explode(':', $rules, 2);
            $parameters = $this->parseParameters($rules, $parameter);
        }
        return [Str::studly(trim($rules)), $parameters];
    }
    protected function parseParameters($rule, $parameter)
    {
        if (strtolower($rule) == 'regex') {
            return [$parameter];
        }
        return str_getcsv($parameter);
    }
    protected function parseNamedParameters($parameters)
    {
        return array_reduce($parameters, function ($result, $item) {
            list($key, $value) = array_pad(explode('=', $item, 2), 2, null);
            $result[$key] = $value;
            return $result;
        });
    }
    protected function normalizeRule($rule)
    {
        switch ($rule) {
            case 'Int':
                return 'Integer';
            case 'Bool':
                return 'Boolean';
            default:
                return $rule;
        }
    }
    protected function dependsOnOtherFields($rule)
    {
        return in_array($rule, $this->dependentRules);
    }
    protected function getExplicitKeys($attribute)
    {
        $pattern = str_replace('\\*', '([^\\.]+)', preg_quote($this->getPrimaryAttribute($attribute)));
        if (preg_match('/^' . $pattern . '/', $attribute, $keys)) {
            array_shift($keys);
            return $keys;
        }
        return [];
    }
    protected function getLeadingExplicitAttributePath($attribute)
    {
        return rtrim(explode('*', $attribute)[0], '.') ?: null;
    }
    protected function extractDataFromPath($attribute)
    {
        $results = [];
        $value = Arr::get($this->data, $attribute, '__missing__');
        if ($value != '__missing__') {
            Arr::set($results, $attribute, $value);
        }
        return $results;
    }
    protected function replaceAsterisksInParameters(array $parameters, array $keys)
    {
        return array_map(function ($field) use($keys) {
            return $this->replaceAsterisksWithKeys($field, $keys);
        }, $parameters);
    }
    protected function replaceAsterisksWithKeys($field, array $keys)
    {
        return vsprintf(str_replace('*', '%s', $field), $keys);
    }
    public function getExtensions()
    {
        return $this->extensions;
    }
    public function addExtensions(array $extensions)
    {
        if ($extensions) {
            $keys = array_map('\\Illuminate\\Support\\Str::snake', array_keys($extensions));
            $extensions = array_combine($keys, array_values($extensions));
        }
        $this->extensions = array_merge($this->extensions, $extensions);
    }
    public function addImplicitExtensions(array $extensions)
    {
        $this->addExtensions($extensions);
        foreach ($extensions as $rule => $extension) {
            $this->implicitRules[] = Str::studly($rule);
        }
    }
    public function addExtension($rule, $extension)
    {
        $this->extensions[Str::snake($rule)] = $extension;
    }
    public function addImplicitExtension($rule, $extension)
    {
        $this->addExtension($rule, $extension);
        $this->implicitRules[] = Str::studly($rule);
    }
    public function getReplacers()
    {
        return $this->replacers;
    }
    public function addReplacers(array $replacers)
    {
        if ($replacers) {
            $keys = array_map('\\Illuminate\\Support\\Str::snake', array_keys($replacers));
            $replacers = array_combine($keys, array_values($replacers));
        }
        $this->replacers = array_merge($this->replacers, $replacers);
    }
    public function addReplacer($rule, $replacer)
    {
        $this->replacers[Str::snake($rule)] = $replacer;
    }
    public function getData()
    {
        return $this->data;
    }
    public function setData(array $data)
    {
        $this->data = $this->parseData($data);
        $this->setRules($this->initialRules);
        return $this;
    }
    public function getRules()
    {
        return $this->rules;
    }
    public function setRules(array $rules)
    {
        $this->initialRules = $rules;
        $this->rules = [];
        $rules = $this->explodeRules($this->initialRules);
        $this->rules = array_merge($this->rules, $rules);
        return $this;
    }
    public function setAttributeNames(array $attributes)
    {
        $this->customAttributes = $attributes;
        return $this;
    }
    public function setValueNames(array $values)
    {
        $this->customValues = $values;
        return $this;
    }
    public function getFiles()
    {
        return $this->files;
    }
    public function setFiles(array $files)
    {
        $this->files = $files;
        return $this;
    }
    public function getPresenceVerifier()
    {
        if (!isset($this->presenceVerifier)) {
            throw new RuntimeException('Presence verifier has not been set.');
        }
        return $this->presenceVerifier;
    }
    public function setPresenceVerifier(PresenceVerifierInterface $presenceVerifier)
    {
        $this->presenceVerifier = $presenceVerifier;
    }
    public function getTranslator()
    {
        return $this->translator;
    }
    public function setTranslator(TranslatorInterface $translator)
    {
        $this->translator = $translator;
    }
    public function getCustomMessages()
    {
        return $this->customMessages;
    }
    public function setCustomMessages(array $messages)
    {
        $this->customMessages = array_merge($this->customMessages, $messages);
    }
    public function getCustomAttributes()
    {
        return $this->customAttributes;
    }
    public function addCustomAttributes(array $customAttributes)
    {
        $this->customAttributes = array_merge($this->customAttributes, $customAttributes);
        return $this;
    }
    public function getCustomValues()
    {
        return $this->customValues;
    }
    public function addCustomValues(array $customValues)
    {
        $this->customValues = array_merge($this->customValues, $customValues);
        return $this;
    }
    public function getFallbackMessages()
    {
        return $this->fallbackMessages;
    }
    public function setFallbackMessages(array $messages)
    {
        $this->fallbackMessages = $messages;
    }
    public function failed()
    {
        return $this->failedRules;
    }
    public function messages()
    {
        if (!$this->messages) {
            $this->passes();
        }
        return $this->messages;
    }
    public function errors()
    {
        return $this->messages();
    }
    public function getMessageBag()
    {
        return $this->messages();
    }
    public function setContainer(Container $container)
    {
        $this->container = $container;
    }
    protected function callExtension($rule, $parameters)
    {
        $callback = $this->extensions[$rule];
        if ($callback instanceof Closure) {
            return call_user_func_array($callback, $parameters);
        } elseif (is_string($callback)) {
            return $this->callClassBasedExtension($callback, $parameters);
        }
    }
    protected function callClassBasedExtension($callback, $parameters)
    {
        if (Str::contains($callback, '@')) {
            list($class, $method) = explode('@', $callback);
        } else {
            list($class, $method) = [$callback, 'validate'];
        }
        return call_user_func_array([$this->container->make($class), $method], $parameters);
    }
    protected function callReplacer($message, $attribute, $rule, $parameters)
    {
        $callback = $this->replacers[$rule];
        if ($callback instanceof Closure) {
            return call_user_func_array($callback, func_get_args());
        } elseif (is_string($callback)) {
            return $this->callClassBasedReplacer($callback, $message, $attribute, $rule, $parameters);
        }
    }
    protected function callClassBasedReplacer($callback, $message, $attribute, $rule, $parameters)
    {
        if (Str::contains($callback, '@')) {
            list($class, $method) = explode('@', $callback);
        } else {
            list($class, $method) = [$callback, 'replace'];
        }
        return call_user_func_array([$this->container->make($class), $method], array_slice(func_get_args(), 1));
    }
    protected function requireParameterCount($count, $parameters, $rule)
    {
        if (count($parameters) < $count) {
            throw new InvalidArgumentException("Validation rule {$rule} requires at least {$count} parameters.");
        }
    }
    public function __call($method, $parameters)
    {
        $rule = Str::snake(substr($method, 8));
        if (isset($this->extensions[$rule])) {
            return $this->callExtension($rule, $parameters);
        }
        throw new BadMethodCallException("Method [{$method}] does not exist.");
    }
}
}

namespace Illuminate\Validation {
use Illuminate\Support\ServiceProvider;
class ValidationServiceProvider extends ServiceProvider
{
    protected $defer = true;
    public function register()
    {
        $this->registerPresenceVerifier();
        $this->registerValidationFactory();
    }
    protected function registerValidationFactory()
    {
        $this->app->singleton('validator', function ($app) {
            $validator = new Factory($app['translator'], $app);
            if (isset($app['validation.presence'])) {
                $validator->setPresenceVerifier($app['validation.presence']);
            }
            return $validator;
        });
    }
    protected function registerPresenceVerifier()
    {
        $this->app->singleton('validation.presence', function ($app) {
            return new DatabasePresenceVerifier($app['db']);
        });
    }
    public function provides()
    {
        return ['validator', 'validation.presence'];
    }
}
}

namespace Illuminate\Validation {
use Illuminate\Support\Str;
use Illuminate\Database\ConnectionResolverInterface;
class DatabasePresenceVerifier implements PresenceVerifierInterface
{
    protected $db;
    protected $connection = null;
    public function __construct(ConnectionResolverInterface $db)
    {
        $this->db = $db;
    }
    public function getCount($collection, $column, $value, $excludeId = null, $idColumn = null, array $extra = [])
    {
        $query = $this->table($collection)->where($column, '=', $value);
        if (!is_null($excludeId) && $excludeId != 'NULL') {
            $query->where($idColumn ?: 'id', '<>', $excludeId);
        }
        foreach ($extra as $key => $extraValue) {
            $this->addWhere($query, $key, $extraValue);
        }
        return $query->count();
    }
    public function getMultiCount($collection, $column, array $values, array $extra = [])
    {
        $query = $this->table($collection)->whereIn($column, $values);
        foreach ($extra as $key => $extraValue) {
            $this->addWhere($query, $key, $extraValue);
        }
        return $query->count();
    }
    protected function addWhere($query, $key, $extraValue)
    {
        if ($extraValue === 'NULL') {
            $query->whereNull($key);
        } elseif ($extraValue === 'NOT_NULL') {
            $query->whereNotNull($key);
        } elseif (Str::startsWith($extraValue, '!')) {
            $query->where($key, '!=', mb_substr($extraValue, 1));
        } else {
            $query->where($key, $extraValue);
        }
    }
    protected function table($table)
    {
        return $this->db->connection($this->connection)->table($table)->useWritePdo();
    }
    public function setConnection($connection)
    {
        $this->connection = $connection;
    }
}
}

namespace Illuminate\Validation {
use Closure;
use Illuminate\Support\Str;
use Illuminate\Contracts\Container\Container;
use Symfony\Component\Translation\TranslatorInterface;
use Illuminate\Contracts\Validation\Factory as FactoryContract;
class Factory implements FactoryContract
{
    protected $translator;
    protected $verifier;
    protected $container;
    protected $extensions = [];
    protected $implicitExtensions = [];
    protected $replacers = [];
    protected $fallbackMessages = [];
    protected $resolver;
    public function __construct(TranslatorInterface $translator, Container $container = null)
    {
        $this->container = $container;
        $this->translator = $translator;
    }
    public function make(array $data, array $rules, array $messages = [], array $customAttributes = [])
    {
        $validator = $this->resolve($data, $rules, $messages, $customAttributes);
        if (!is_null($this->verifier)) {
            $validator->setPresenceVerifier($this->verifier);
        }
        if (!is_null($this->container)) {
            $validator->setContainer($this->container);
        }
        $this->addExtensions($validator);
        return $validator;
    }
    public function validate(array $data, array $rules, array $messages = [], array $customAttributes = [])
    {
        $this->make($data, $rules, $messages, $customAttributes)->validate();
    }
    protected function addExtensions(Validator $validator)
    {
        $validator->addExtensions($this->extensions);
        $implicit = $this->implicitExtensions;
        $validator->addImplicitExtensions($implicit);
        $validator->addReplacers($this->replacers);
        $validator->setFallbackMessages($this->fallbackMessages);
    }
    protected function resolve(array $data, array $rules, array $messages, array $customAttributes)
    {
        if (is_null($this->resolver)) {
            return new Validator($this->translator, $data, $rules, $messages, $customAttributes);
        }
        return call_user_func($this->resolver, $this->translator, $data, $rules, $messages, $customAttributes);
    }
    public function extend($rule, $extension, $message = null)
    {
        $this->extensions[$rule] = $extension;
        if ($message) {
            $this->fallbackMessages[Str::snake($rule)] = $message;
        }
    }
    public function extendImplicit($rule, $extension, $message = null)
    {
        $this->implicitExtensions[$rule] = $extension;
        if ($message) {
            $this->fallbackMessages[Str::snake($rule)] = $message;
        }
    }
    public function replacer($rule, $replacer)
    {
        $this->replacers[$rule] = $replacer;
    }
    public function resolver(Closure $resolver)
    {
        $this->resolver = $resolver;
    }
    public function getTranslator()
    {
        return $this->translator;
    }
    public function getPresenceVerifier()
    {
        return $this->verifier;
    }
    public function setPresenceVerifier(PresenceVerifierInterface $presenceVerifier)
    {
        $this->verifier = $presenceVerifier;
    }
}
}

namespace Illuminate\Validation {
trait ValidatesWhenResolvedTrait
{
    public function validate()
    {
        $instance = $this->getValidatorInstance();
        if (!$this->passesAuthorization()) {
            $this->failedAuthorization();
        } elseif (!$instance->passes()) {
            $this->failedValidation($instance);
        }
    }
    protected function getValidatorInstance()
    {
        return $this->validator();
    }
    protected function failedValidation(Validator $validator)
    {
        throw new ValidationException($validator);
    }
    protected function passesAuthorization()
    {
        if (method_exists($this, 'authorize')) {
            return $this->authorize();
        }
        return true;
    }
    protected function failedAuthorization()
    {
        throw new UnauthorizedException();
    }
}
}

namespace Illuminate\Validation {
interface PresenceVerifierInterface
{
    public function getCount($collection, $column, $value, $excludeId = null, $idColumn = null, array $extra = []);
    public function getMultiCount($collection, $column, array $values, array $extra = []);
}
}

namespace Illuminate\Validation {
use Exception;
class ValidationException extends Exception
{
    public $validator;
    public $response;
    public function __construct($validator, $response = null)
    {
        parent::__construct('The given data failed to pass validation.');
        $this->response = $response;
        $this->validator = $validator;
    }
    public function getResponse()
    {
        return $this->response;
    }
}
}

namespace Illuminate\Pagination {
use Closure;
use ArrayIterator;
use Illuminate\Support\Str;
use Illuminate\Support\Collection;
use Illuminate\Contracts\Support\Htmlable;
abstract class AbstractPaginator implements Htmlable
{
    protected $items;
    protected $perPage;
    protected $currentPage;
    protected $path = '/';
    protected $query = [];
    protected $fragment = null;
    protected $pageName = 'page';
    protected static $currentPathResolver;
    protected static $currentPageResolver;
    protected static $viewFactoryResolver;
    public static $defaultView = 'pagination::default';
    public static $defaultSimpleView = 'pagination::simple-default';
    protected function isValidPageNumber($page)
    {
        return $page >= 1 && filter_var($page, FILTER_VALIDATE_INT) !== false;
    }
    public function getUrlRange($start, $end)
    {
        $urls = [];
        for ($page = $start; $page <= $end; $page++) {
            $urls[$page] = $this->url($page);
        }
        return $urls;
    }
    public function url($page)
    {
        if ($page <= 0) {
            $page = 1;
        }
        $parameters = [$this->pageName => $page];
        if (count($this->query) > 0) {
            $parameters = array_merge($this->query, $parameters);
        }
        return $this->path . (Str::contains($this->path, '?') ? '&' : '?') . http_build_query($parameters, '', '&') . $this->buildFragment();
    }
    public function previousPageUrl()
    {
        if ($this->currentPage() > 1) {
            return $this->url($this->currentPage() - 1);
        }
    }
    public function fragment($fragment = null)
    {
        if (is_null($fragment)) {
            return $this->fragment;
        }
        $this->fragment = $fragment;
        return $this;
    }
    public function appends($key, $value = null)
    {
        if (is_array($key)) {
            return $this->appendArray($key);
        }
        return $this->addQuery($key, $value);
    }
    protected function appendArray(array $keys)
    {
        foreach ($keys as $key => $value) {
            $this->addQuery($key, $value);
        }
        return $this;
    }
    public function addQuery($key, $value)
    {
        if ($key !== $this->pageName) {
            $this->query[$key] = $value;
        }
        return $this;
    }
    protected function buildFragment()
    {
        return $this->fragment ? '#' . $this->fragment : '';
    }
    public function items()
    {
        return $this->items->all();
    }
    public function firstItem()
    {
        if (count($this->items) === 0) {
            return;
        }
        return ($this->currentPage - 1) * $this->perPage + 1;
    }
    public function lastItem()
    {
        if (count($this->items) === 0) {
            return;
        }
        return $this->firstItem() + $this->count() - 1;
    }
    public function perPage()
    {
        return $this->perPage;
    }
    public function onFirstPage()
    {
        return $this->currentPage() <= 1;
    }
    public function currentPage()
    {
        return $this->currentPage;
    }
    public function hasPages()
    {
        return !($this->currentPage() == 1 && !$this->hasMorePages());
    }
    public static function resolveCurrentPath($default = '/')
    {
        if (isset(static::$currentPathResolver)) {
            return call_user_func(static::$currentPathResolver);
        }
        return $default;
    }
    public static function currentPathResolver(Closure $resolver)
    {
        static::$currentPathResolver = $resolver;
    }
    public static function resolveCurrentPage($pageName = 'page', $default = 1)
    {
        if (isset(static::$currentPageResolver)) {
            return call_user_func(static::$currentPageResolver, $pageName);
        }
        return $default;
    }
    public static function currentPageResolver(Closure $resolver)
    {
        static::$currentPageResolver = $resolver;
    }
    public static function viewFactory()
    {
        return call_user_func(static::$viewFactoryResolver);
    }
    public static function viewFactoryResolver(Closure $resolver)
    {
        static::$viewFactoryResolver = $resolver;
    }
    public static function defaultView($view)
    {
        static::$defaultView = $view;
    }
    public static function defaultSimpleView($view)
    {
        static::$defaultSimpleView = $view;
    }
    public function getPageName()
    {
        return $this->pageName;
    }
    public function setPageName($name)
    {
        $this->pageName = $name;
        return $this;
    }
    public function setPath($path)
    {
        $this->path = $path;
        return $this;
    }
    public function getIterator()
    {
        return new ArrayIterator($this->items->all());
    }
    public function isEmpty()
    {
        return $this->items->isEmpty();
    }
    public function count()
    {
        return $this->items->count();
    }
    public function getCollection()
    {
        return $this->items;
    }
    public function setCollection(Collection $collection)
    {
        $this->items = $collection;
        return $this;
    }
    public function offsetExists($key)
    {
        return $this->items->has($key);
    }
    public function offsetGet($key)
    {
        return $this->items->get($key);
    }
    public function offsetSet($key, $value)
    {
        $this->items->put($key, $value);
    }
    public function offsetUnset($key)
    {
        $this->items->forget($key);
    }
    public function toHtml()
    {
        return (string) $this->render();
    }
    public function __call($method, $parameters)
    {
        return $this->getCollection()->{$method}(...$parameters);
    }
    public function __toString()
    {
        return (string) $this->render();
    }
}
}

namespace Illuminate\Pagination {
use Countable;
use ArrayAccess;
use JsonSerializable;
use IteratorAggregate;
use Illuminate\Support\HtmlString;
use Illuminate\Support\Collection;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Pagination\Paginator as PaginatorContract;
class Paginator extends AbstractPaginator implements Arrayable, ArrayAccess, Countable, IteratorAggregate, JsonSerializable, Jsonable, PaginatorContract
{
    protected $hasMore;
    public function __construct($items, $perPage, $currentPage = null, array $options = [])
    {
        foreach ($options as $key => $value) {
            $this->{$key} = $value;
        }
        $this->perPage = $perPage;
        $this->currentPage = $this->setCurrentPage($currentPage);
        $this->path = $this->path != '/' ? rtrim($this->path, '/') : $this->path;
        $this->items = $items instanceof Collection ? $items : Collection::make($items);
        $this->checkForMorePages();
    }
    protected function setCurrentPage($currentPage)
    {
        $currentPage = $currentPage ?: static::resolveCurrentPage();
        return $this->isValidPageNumber($currentPage) ? (int) $currentPage : 1;
    }
    protected function checkForMorePages()
    {
        $this->hasMore = count($this->items) > $this->perPage;
        $this->items = $this->items->slice(0, $this->perPage);
    }
    public function nextPageUrl()
    {
        if ($this->hasMorePages()) {
            return $this->url($this->currentPage() + 1);
        }
    }
    public function hasMorePagesWhen($value = true)
    {
        $this->hasMore = $value;
        return $this;
    }
    public function hasMorePages()
    {
        return $this->hasMore;
    }
    public function links($view = null)
    {
        return $this->render($view);
    }
    public function render($view = null)
    {
        return new HtmlString(static::viewFactory()->make($view ?: static::$defaultSimpleView, ['paginator' => $this])->render());
    }
    public function toArray()
    {
        return ['per_page' => $this->perPage(), 'current_page' => $this->currentPage(), 'next_page_url' => $this->nextPageUrl(), 'prev_page_url' => $this->previousPageUrl(), 'from' => $this->firstItem(), 'to' => $this->lastItem(), 'data' => $this->items->toArray()];
    }
    public function jsonSerialize()
    {
        return $this->toArray();
    }
    public function toJson($options = 0)
    {
        return json_encode($this->jsonSerialize(), $options);
    }
}
}

namespace Illuminate\Hashing {
use Illuminate\Support\ServiceProvider;
class HashServiceProvider extends ServiceProvider
{
    protected $defer = true;
    public function register()
    {
        $this->app->singleton('hash', function () {
            return new BcryptHasher();
        });
    }
    public function provides()
    {
        return ['hash'];
    }
}
}

namespace Illuminate\Hashing {
use RuntimeException;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
class BcryptHasher implements HasherContract
{
    protected $rounds = 10;
    public function make($value, array $options = [])
    {
        $cost = isset($options['rounds']) ? $options['rounds'] : $this->rounds;
        $hash = password_hash($value, PASSWORD_BCRYPT, ['cost' => $cost]);
        if ($hash === false) {
            throw new RuntimeException('Bcrypt hashing not supported.');
        }
        return $hash;
    }
    public function check($value, $hashedValue, array $options = [])
    {
        if (strlen($hashedValue) === 0) {
            return false;
        }
        return password_verify($value, $hashedValue);
    }
    public function needsRehash($hashedValue, array $options = [])
    {
        $cost = isset($options['rounds']) ? $options['rounds'] : $this->rounds;
        return password_needs_rehash($hashedValue, PASSWORD_BCRYPT, ['cost' => $cost]);
    }
    public function setRounds($rounds)
    {
        $this->rounds = (int) $rounds;
        return $this;
    }
}
}

namespace Illuminate\Config {
use ArrayAccess;
use Illuminate\Support\Arr;
use Illuminate\Contracts\Config\Repository as ConfigContract;
class Repository implements ArrayAccess, ConfigContract
{
    protected $items = [];
    public function __construct(array $items = [])
    {
        $this->items = $items;
    }
    public function has($key)
    {
        return Arr::has($this->items, $key);
    }
    public function get($key, $default = null)
    {
        return Arr::get($this->items, $key, $default);
    }
    public function set($key, $value = null)
    {
        if (is_array($key)) {
            foreach ($key as $innerKey => $innerValue) {
                Arr::set($this->items, $innerKey, $innerValue);
            }
        } else {
            Arr::set($this->items, $key, $value);
        }
    }
    public function prepend($key, $value)
    {
        $array = $this->get($key);
        array_unshift($array, $value);
        $this->set($key, $array);
    }
    public function push($key, $value)
    {
        $array = $this->get($key);
        $array[] = $value;
        $this->set($key, $array);
    }
    public function all()
    {
        return $this->items;
    }
    public function offsetExists($key)
    {
        return $this->has($key);
    }
    public function offsetGet($key)
    {
        return $this->get($key);
    }
    public function offsetSet($key, $value)
    {
        $this->set($key, $value);
    }
    public function offsetUnset($key)
    {
        $this->set($key, null);
    }
}
}

namespace Illuminate\Filesystem {
use ErrorException;
use FilesystemIterator;
use Symfony\Component\Finder\Finder;
use Illuminate\Support\Traits\Macroable;
use Illuminate\Contracts\Filesystem\FileNotFoundException;
class Filesystem
{
    use Macroable;
    public function exists($path)
    {
        return file_exists($path);
    }
    public function get($path, $lock = false)
    {
        if ($this->isFile($path)) {
            return $lock ? $this->sharedGet($path) : file_get_contents($path);
        }
        throw new FileNotFoundException("File does not exist at path {$path}");
    }
    public function sharedGet($path)
    {
        $contents = '';
        $handle = fopen($path, 'rb');
        if ($handle) {
            try {
                if (flock($handle, LOCK_SH)) {
                    clearstatcache(true, $path);
                    $contents = fread($handle, $this->size($path) ?: 1);
                    flock($handle, LOCK_UN);
                }
            } finally {
                fclose($handle);
            }
        }
        return $contents;
    }
    public function getRequire($path)
    {
        if ($this->isFile($path)) {
            return require $path;
        }
        throw new FileNotFoundException("File does not exist at path {$path}");
    }
    public function requireOnce($file)
    {
        require_once $file;
    }
    public function put($path, $contents, $lock = false)
    {
        return file_put_contents($path, $contents, $lock ? LOCK_EX : 0);
    }
    public function prepend($path, $data)
    {
        if ($this->exists($path)) {
            return $this->put($path, $data . $this->get($path));
        }
        return $this->put($path, $data);
    }
    public function append($path, $data)
    {
        return file_put_contents($path, $data, FILE_APPEND);
    }
    public function delete($paths)
    {
        $paths = is_array($paths) ? $paths : func_get_args();
        $success = true;
        foreach ($paths as $path) {
            try {
                if (!@unlink($path)) {
                    $success = false;
                }
            } catch (ErrorException $e) {
                $success = false;
            }
        }
        return $success;
    }
    public function move($path, $target)
    {
        return rename($path, $target);
    }
    public function copy($path, $target)
    {
        return copy($path, $target);
    }
    public function link($target, $link)
    {
        if (!windows_os()) {
            return symlink($target, $link);
        }
        $mode = $this->isDirectory($target) ? 'J' : 'H';
        exec("mklink /{$mode} \"{$link}\" \"{$target}\"");
    }
    public function name($path)
    {
        return pathinfo($path, PATHINFO_FILENAME);
    }
    public function basename($path)
    {
        return pathinfo($path, PATHINFO_BASENAME);
    }
    public function dirname($path)
    {
        return pathinfo($path, PATHINFO_DIRNAME);
    }
    public function extension($path)
    {
        return pathinfo($path, PATHINFO_EXTENSION);
    }
    public function type($path)
    {
        return filetype($path);
    }
    public function mimeType($path)
    {
        return finfo_file(finfo_open(FILEINFO_MIME_TYPE), $path);
    }
    public function size($path)
    {
        return filesize($path);
    }
    public function lastModified($path)
    {
        return filemtime($path);
    }
    public function isDirectory($directory)
    {
        return is_dir($directory);
    }
    public function isReadable($path)
    {
        return is_readable($path);
    }
    public function isWritable($path)
    {
        return is_writable($path);
    }
    public function isFile($file)
    {
        return is_file($file);
    }
    public function glob($pattern, $flags = 0)
    {
        return glob($pattern, $flags);
    }
    public function files($directory)
    {
        $glob = glob($directory . '/*');
        if ($glob === false) {
            return [];
        }
        return array_filter($glob, function ($file) {
            return filetype($file) == 'file';
        });
    }
    public function allFiles($directory, $hidden = false)
    {
        return iterator_to_array(Finder::create()->files()->ignoreDotFiles(!$hidden)->in($directory), false);
    }
    public function directories($directory)
    {
        $directories = [];
        foreach (Finder::create()->in($directory)->directories()->depth(0) as $dir) {
            $directories[] = $dir->getPathname();
        }
        return $directories;
    }
    public function makeDirectory($path, $mode = 0755, $recursive = false, $force = false)
    {
        if ($force) {
            return @mkdir($path, $mode, $recursive);
        }
        return mkdir($path, $mode, $recursive);
    }
    public function moveDirectory($from, $to, $overwrite = false)
    {
        if ($overwrite && $this->isDirectory($to)) {
            if (!$this->deleteDirectory($to)) {
                return false;
            }
        }
        return @rename($from, $to) === true;
    }
    public function copyDirectory($directory, $destination, $options = null)
    {
        if (!$this->isDirectory($directory)) {
            return false;
        }
        $options = $options ?: FilesystemIterator::SKIP_DOTS;
        if (!$this->isDirectory($destination)) {
            $this->makeDirectory($destination, 0777, true);
        }
        $items = new FilesystemIterator($directory, $options);
        foreach ($items as $item) {
            $target = $destination . '/' . $item->getBasename();
            if ($item->isDir()) {
                $path = $item->getPathname();
                if (!$this->copyDirectory($path, $target, $options)) {
                    return false;
                }
            } else {
                if (!$this->copy($item->getPathname(), $target)) {
                    return false;
                }
            }
        }
        return true;
    }
    public function deleteDirectory($directory, $preserve = false)
    {
        if (!$this->isDirectory($directory)) {
            return false;
        }
        $items = new FilesystemIterator($directory);
        foreach ($items as $item) {
            if ($item->isDir() && !$item->isLink()) {
                $this->deleteDirectory($item->getPathname());
            } else {
                $this->delete($item->getPathname());
            }
        }
        if (!$preserve) {
            @rmdir($directory);
        }
        return true;
    }
    public function cleanDirectory($directory)
    {
        return $this->deleteDirectory($directory, true);
    }
}
}

namespace Illuminate\Filesystem {
use Illuminate\Support\ServiceProvider;
class FilesystemServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->registerNativeFilesystem();
        $this->registerFlysystem();
    }
    protected function registerNativeFilesystem()
    {
        $this->app->singleton('files', function () {
            return new Filesystem();
        });
    }
    protected function registerFlysystem()
    {
        $this->registerManager();
        $this->app->singleton('filesystem.disk', function () {
            return $this->app['filesystem']->disk($this->getDefaultDriver());
        });
        $this->app->singleton('filesystem.cloud', function () {
            return $this->app['filesystem']->disk($this->getCloudDriver());
        });
    }
    protected function registerManager()
    {
        $this->app->singleton('filesystem', function () {
            return new FilesystemManager($this->app);
        });
    }
    protected function getDefaultDriver()
    {
        return $this->app['config']['filesystems.default'];
    }
    protected function getCloudDriver()
    {
        return $this->app['config']['filesystems.cloud'];
    }
}
}

namespace Illuminate\Pipeline {
use Closure;
use RuntimeException;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Pipeline\Pipeline as PipelineContract;
class Pipeline implements PipelineContract
{
    protected $container;
    protected $passable;
    protected $pipes = [];
    protected $method = 'handle';
    public function __construct(Container $container = null)
    {
        $this->container = $container;
    }
    public function send($passable)
    {
        $this->passable = $passable;
        return $this;
    }
    public function through($pipes)
    {
        $this->pipes = is_array($pipes) ? $pipes : func_get_args();
        return $this;
    }
    public function via($method)
    {
        $this->method = $method;
        return $this;
    }
    public function then(Closure $destination)
    {
        $firstSlice = $this->getInitialSlice($destination);
        $callable = array_reduce(array_reverse($this->pipes), $this->getSlice(), $firstSlice);
        return $callable($this->passable);
    }
    protected function getSlice()
    {
        return function ($stack, $pipe) {
            return function ($passable) use($stack, $pipe) {
                if ($pipe instanceof Closure) {
                    return $pipe($passable, $stack);
                } elseif (!is_object($pipe)) {
                    list($name, $parameters) = $this->parsePipeString($pipe);
                    $pipe = $this->getContainer()->make($name);
                    $parameters = array_merge([$passable, $stack], $parameters);
                } else {
                    $parameters = [$passable, $stack];
                }
                return $pipe->{$this->method}(...$parameters);
            };
        };
    }
    protected function getInitialSlice(Closure $destination)
    {
        return function ($passable) use($destination) {
            return $destination($passable);
        };
    }
    protected function parsePipeString($pipe)
    {
        list($name, $parameters) = array_pad(explode(':', $pipe, 2), 2, []);
        if (is_string($parameters)) {
            $parameters = explode(',', $parameters);
        }
        return [$name, $parameters];
    }
    protected function getContainer()
    {
        if (!$this->container) {
            throw new RuntimeException('A container instance has not been passed to the Pipeline.');
        }
        return $this->container;
    }
}
}

namespace Illuminate\Database {
use PDO;
use Closure;
use Exception;
use Throwable;
use LogicException;
use RuntimeException;
use DateTimeInterface;
use Illuminate\Support\Arr;
use Illuminate\Database\Query\Expression;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Query\Processors\Processor;
use Doctrine\DBAL\Connection as DoctrineConnection;
use Illuminate\Database\Query\Builder as QueryBuilder;
use Illuminate\Database\Schema\Builder as SchemaBuilder;
use Illuminate\Database\Query\Grammars\Grammar as QueryGrammar;
class Connection implements ConnectionInterface
{
    use DetectsDeadlocks, DetectsLostConnections;
    protected $pdo;
    protected $readPdo;
    protected $reconnector;
    protected $queryGrammar;
    protected $schemaGrammar;
    protected $postProcessor;
    protected $events;
    protected $fetchMode = PDO::FETCH_OBJ;
    protected $fetchArgument;
    protected $fetchConstructorArgument = [];
    protected $transactions = 0;
    protected $queryLog = [];
    protected $loggingQueries = false;
    protected $pretending = false;
    protected $database;
    protected $doctrineConnection;
    protected $tablePrefix = '';
    protected $config = [];
    public function __construct($pdo, $database = '', $tablePrefix = '', array $config = [])
    {
        $this->pdo = $pdo;
        $this->database = $database;
        $this->tablePrefix = $tablePrefix;
        $this->config = $config;
        $this->useDefaultQueryGrammar();
        $this->useDefaultPostProcessor();
    }
    public function useDefaultQueryGrammar()
    {
        $this->queryGrammar = $this->getDefaultQueryGrammar();
    }
    protected function getDefaultQueryGrammar()
    {
        return new QueryGrammar();
    }
    public function useDefaultSchemaGrammar()
    {
        $this->schemaGrammar = $this->getDefaultSchemaGrammar();
    }
    protected function getDefaultSchemaGrammar()
    {
    }
    public function useDefaultPostProcessor()
    {
        $this->postProcessor = $this->getDefaultPostProcessor();
    }
    protected function getDefaultPostProcessor()
    {
        return new Processor();
    }
    public function getSchemaBuilder()
    {
        if (is_null($this->schemaGrammar)) {
            $this->useDefaultSchemaGrammar();
        }
        return new SchemaBuilder($this);
    }
    public function table($table)
    {
        return $this->query()->from($table);
    }
    public function query()
    {
        return new QueryBuilder($this, $this->getQueryGrammar(), $this->getPostProcessor());
    }
    public function raw($value)
    {
        return new Expression($value);
    }
    public function selectOne($query, $bindings = [])
    {
        $records = $this->select($query, $bindings);
        return count($records) > 0 ? reset($records) : null;
    }
    public function selectFromWriteConnection($query, $bindings = [])
    {
        return $this->select($query, $bindings, false);
    }
    public function select($query, $bindings = [], $useReadPdo = true)
    {
        return $this->run($query, $bindings, function ($me, $query, $bindings) use($useReadPdo) {
            if ($me->pretending()) {
                return [];
            }
            $statement = $this->getPdoForSelect($useReadPdo)->prepare($query);
            $me->bindValues($statement, $me->prepareBindings($bindings));
            $statement->execute();
            $fetchMode = $me->getFetchMode();
            $fetchArgument = $me->getFetchArgument();
            $fetchConstructorArgument = $me->getFetchConstructorArgument();
            if ($fetchMode === PDO::FETCH_CLASS && !isset($fetchArgument)) {
                $fetchArgument = 'StdClass';
                $fetchConstructorArgument = null;
            }
            return isset($fetchArgument) ? $statement->fetchAll($fetchMode, $fetchArgument, $fetchConstructorArgument) : $statement->fetchAll($fetchMode);
        });
    }
    public function cursor($query, $bindings = [], $useReadPdo = true)
    {
        $statement = $this->run($query, $bindings, function ($me, $query, $bindings) use($useReadPdo) {
            if ($me->pretending()) {
                return [];
            }
            $statement = $this->getPdoForSelect($useReadPdo)->prepare($query);
            $fetchMode = $me->getFetchMode();
            $fetchArgument = $me->getFetchArgument();
            $fetchConstructorArgument = $me->getFetchConstructorArgument();
            if ($fetchMode === PDO::FETCH_CLASS && !isset($fetchArgument)) {
                $fetchArgument = 'StdClass';
                $fetchConstructorArgument = null;
            }
            if (isset($fetchArgument)) {
                $statement->setFetchMode($fetchMode, $fetchArgument, $fetchConstructorArgument);
            } else {
                $statement->setFetchMode($fetchMode);
            }
            $me->bindValues($statement, $me->prepareBindings($bindings));
            $statement->execute();
            return $statement;
        });
        while ($record = $statement->fetch()) {
            (yield $record);
        }
    }
    public function bindValues($statement, $bindings)
    {
        foreach ($bindings as $key => $value) {
            $statement->bindValue(is_string($key) ? $key : $key + 1, $value, is_int($value) ? PDO::PARAM_INT : PDO::PARAM_STR);
        }
    }
    protected function getPdoForSelect($useReadPdo = true)
    {
        return $useReadPdo ? $this->getReadPdo() : $this->getPdo();
    }
    public function insert($query, $bindings = [])
    {
        return $this->statement($query, $bindings);
    }
    public function update($query, $bindings = [])
    {
        return $this->affectingStatement($query, $bindings);
    }
    public function delete($query, $bindings = [])
    {
        return $this->affectingStatement($query, $bindings);
    }
    public function statement($query, $bindings = [])
    {
        return $this->run($query, $bindings, function ($me, $query, $bindings) {
            if ($me->pretending()) {
                return true;
            }
            $statement = $this->getPdo()->prepare($query);
            $this->bindValues($statement, $me->prepareBindings($bindings));
            return $statement->execute();
        });
    }
    public function affectingStatement($query, $bindings = [])
    {
        return $this->run($query, $bindings, function ($me, $query, $bindings) {
            if ($me->pretending()) {
                return 0;
            }
            $statement = $me->getPdo()->prepare($query);
            $this->bindValues($statement, $me->prepareBindings($bindings));
            $statement->execute();
            return $statement->rowCount();
        });
    }
    public function unprepared($query)
    {
        return $this->run($query, [], function ($me, $query) {
            if ($me->pretending()) {
                return true;
            }
            return (bool) $me->getPdo()->exec($query);
        });
    }
    public function prepareBindings(array $bindings)
    {
        $grammar = $this->getQueryGrammar();
        foreach ($bindings as $key => $value) {
            if ($value instanceof DateTimeInterface) {
                $bindings[$key] = $value->format($grammar->getDateFormat());
            } elseif ($value === false) {
                $bindings[$key] = 0;
            }
        }
        return $bindings;
    }
    public function transaction(Closure $callback, $attempts = 1)
    {
        for ($a = 1; $a <= $attempts; $a++) {
            $this->beginTransaction();
            try {
                $result = $callback($this);
                $this->commit();
            } catch (Exception $e) {
                $this->rollBack();
                if ($this->causedByDeadlock($e) && $a < $attempts) {
                    continue;
                }
                throw $e;
            } catch (Throwable $e) {
                $this->rollBack();
                throw $e;
            }
            return $result;
        }
    }
    public function beginTransaction()
    {
        ++$this->transactions;
        if ($this->transactions == 1) {
            try {
                $this->getPdo()->beginTransaction();
            } catch (Exception $e) {
                --$this->transactions;
                throw $e;
            }
        } elseif ($this->transactions > 1 && $this->queryGrammar->supportsSavepoints()) {
            $this->getPdo()->exec($this->queryGrammar->compileSavepoint('trans' . $this->transactions));
        }
        $this->fireConnectionEvent('beganTransaction');
    }
    public function commit()
    {
        if ($this->transactions == 1) {
            $this->getPdo()->commit();
        }
        $this->transactions = max(0, $this->transactions - 1);
        $this->fireConnectionEvent('committed');
    }
    public function rollBack()
    {
        if ($this->transactions == 1) {
            $this->getPdo()->rollBack();
        } elseif ($this->transactions > 1 && $this->queryGrammar->supportsSavepoints()) {
            $this->getPdo()->exec($this->queryGrammar->compileSavepointRollBack('trans' . $this->transactions));
        }
        $this->transactions = max(0, $this->transactions - 1);
        $this->fireConnectionEvent('rollingBack');
    }
    public function transactionLevel()
    {
        return $this->transactions;
    }
    public function pretend(Closure $callback)
    {
        $loggingQueries = $this->loggingQueries;
        $this->enableQueryLog();
        $this->pretending = true;
        $this->queryLog = [];
        $callback($this);
        $this->pretending = false;
        $this->loggingQueries = $loggingQueries;
        return $this->queryLog;
    }
    protected function run($query, $bindings, Closure $callback)
    {
        $this->reconnectIfMissingConnection();
        $start = microtime(true);
        try {
            $result = $this->runQueryCallback($query, $bindings, $callback);
        } catch (QueryException $e) {
            if ($this->transactions >= 1) {
                throw $e;
            }
            $result = $this->tryAgainIfCausedByLostConnection($e, $query, $bindings, $callback);
        }
        $time = $this->getElapsedTime($start);
        $this->logQuery($query, $bindings, $time);
        return $result;
    }
    protected function runQueryCallback($query, $bindings, Closure $callback)
    {
        try {
            $result = $callback($this, $query, $bindings);
        } catch (Exception $e) {
            throw new QueryException($query, $this->prepareBindings($bindings), $e);
        }
        return $result;
    }
    protected function tryAgainIfCausedByLostConnection(QueryException $e, $query, $bindings, Closure $callback)
    {
        if ($this->causedByLostConnection($e->getPrevious())) {
            $this->reconnect();
            return $this->runQueryCallback($query, $bindings, $callback);
        }
        throw $e;
    }
    public function disconnect()
    {
        $this->setPdo(null)->setReadPdo(null);
    }
    public function reconnect()
    {
        if (is_callable($this->reconnector)) {
            return call_user_func($this->reconnector, $this);
        }
        throw new LogicException('Lost connection and no reconnector available.');
    }
    protected function reconnectIfMissingConnection()
    {
        if (is_null($this->getPdo()) || is_null($this->getReadPdo())) {
            $this->reconnect();
        }
    }
    public function logQuery($query, $bindings, $time = null)
    {
        if (isset($this->events)) {
            $this->events->fire(new Events\QueryExecuted($query, $bindings, $time, $this));
        }
        if ($this->loggingQueries) {
            $this->queryLog[] = compact('query', 'bindings', 'time');
        }
    }
    public function listen(Closure $callback)
    {
        if (isset($this->events)) {
            $this->events->listen(Events\QueryExecuted::class, $callback);
        }
    }
    protected function fireConnectionEvent($event)
    {
        if (!isset($this->events)) {
            return;
        }
        switch ($event) {
            case 'beganTransaction':
                return $this->events->fire(new Events\TransactionBeginning($this));
            case 'committed':
                return $this->events->fire(new Events\TransactionCommitted($this));
            case 'rollingBack':
                return $this->events->fire(new Events\TransactionRolledBack($this));
        }
    }
    protected function getElapsedTime($start)
    {
        return round((microtime(true) - $start) * 1000, 2);
    }
    public function isDoctrineAvailable()
    {
        return class_exists('Doctrine\\DBAL\\Connection');
    }
    public function getDoctrineColumn($table, $column)
    {
        $schema = $this->getDoctrineSchemaManager();
        return $schema->listTableDetails($table)->getColumn($column);
    }
    public function getDoctrineSchemaManager()
    {
        return $this->getDoctrineDriver()->getSchemaManager($this->getDoctrineConnection());
    }
    public function getDoctrineConnection()
    {
        if (is_null($this->doctrineConnection)) {
            $driver = $this->getDoctrineDriver();
            $data = ['pdo' => $this->getPdo(), 'dbname' => $this->getConfig('database')];
            $this->doctrineConnection = new DoctrineConnection($data, $driver);
        }
        return $this->doctrineConnection;
    }
    public function getPdo()
    {
        if ($this->pdo instanceof Closure) {
            return $this->pdo = call_user_func($this->pdo);
        }
        return $this->pdo;
    }
    public function getReadPdo()
    {
        if ($this->transactions >= 1) {
            return $this->getPdo();
        }
        if ($this->readPdo instanceof Closure) {
            return $this->readPdo = call_user_func($this->readPdo);
        }
        return $this->readPdo ?: $this->getPdo();
    }
    public function setPdo($pdo)
    {
        if ($this->transactions >= 1) {
            throw new RuntimeException("Can't swap PDO instance while within transaction.");
        }
        $this->pdo = $pdo;
        return $this;
    }
    public function setReadPdo($pdo)
    {
        $this->readPdo = $pdo;
        return $this;
    }
    public function setReconnector(callable $reconnector)
    {
        $this->reconnector = $reconnector;
        return $this;
    }
    public function getName()
    {
        return $this->getConfig('name');
    }
    public function getConfig($option)
    {
        return Arr::get($this->config, $option);
    }
    public function getDriverName()
    {
        return $this->getConfig('driver');
    }
    public function getQueryGrammar()
    {
        return $this->queryGrammar;
    }
    public function setQueryGrammar(Query\Grammars\Grammar $grammar)
    {
        $this->queryGrammar = $grammar;
    }
    public function getSchemaGrammar()
    {
        return $this->schemaGrammar;
    }
    public function setSchemaGrammar(Schema\Grammars\Grammar $grammar)
    {
        $this->schemaGrammar = $grammar;
    }
    public function getPostProcessor()
    {
        return $this->postProcessor;
    }
    public function setPostProcessor(Processor $processor)
    {
        $this->postProcessor = $processor;
    }
    public function getEventDispatcher()
    {
        return $this->events;
    }
    public function setEventDispatcher(Dispatcher $events)
    {
        $this->events = $events;
    }
    public function pretending()
    {
        return $this->pretending === true;
    }
    public function getFetchMode()
    {
        return $this->fetchMode;
    }
    public function getFetchArgument()
    {
        return $this->fetchArgument;
    }
    public function getFetchConstructorArgument()
    {
        return $this->fetchConstructorArgument;
    }
    public function setFetchMode($fetchMode, $fetchArgument = null, array $fetchConstructorArgument = [])
    {
        $this->fetchMode = $fetchMode;
        $this->fetchArgument = $fetchArgument;
        $this->fetchConstructorArgument = $fetchConstructorArgument;
    }
    public function getQueryLog()
    {
        return $this->queryLog;
    }
    public function flushQueryLog()
    {
        $this->queryLog = [];
    }
    public function enableQueryLog()
    {
        $this->loggingQueries = true;
    }
    public function disableQueryLog()
    {
        $this->loggingQueries = false;
    }
    public function logging()
    {
        return $this->loggingQueries;
    }
    public function getDatabaseName()
    {
        return $this->database;
    }
    public function setDatabaseName($database)
    {
        $this->database = $database;
    }
    public function getTablePrefix()
    {
        return $this->tablePrefix;
    }
    public function setTablePrefix($prefix)
    {
        $this->tablePrefix = $prefix;
        $this->getQueryGrammar()->setTablePrefix($prefix);
    }
    public function withTablePrefix(Grammar $grammar)
    {
        $grammar->setTablePrefix($this->tablePrefix);
        return $grammar;
    }
}
}

namespace Illuminate\Database {
use Illuminate\Database\Query\Expression;
abstract class Grammar
{
    protected $tablePrefix = '';
    public function wrapArray(array $values)
    {
        return array_map([$this, 'wrap'], $values);
    }
    public function wrapTable($table)
    {
        if ($this->isExpression($table)) {
            return $this->getValue($table);
        }
        return $this->wrap($this->tablePrefix . $table, true);
    }
    public function wrap($value, $prefixAlias = false)
    {
        if ($this->isExpression($value)) {
            return $this->getValue($value);
        }
        if (strpos(strtolower($value), ' as ') !== false) {
            $segments = explode(' ', $value);
            if ($prefixAlias) {
                $segments[2] = $this->tablePrefix . $segments[2];
            }
            return $this->wrap($segments[0]) . ' as ' . $this->wrapValue($segments[2]);
        }
        $wrapped = [];
        $segments = explode('.', $value);
        foreach ($segments as $key => $segment) {
            if ($key == 0 && count($segments) > 1) {
                $wrapped[] = $this->wrapTable($segment);
            } else {
                $wrapped[] = $this->wrapValue($segment);
            }
        }
        return implode('.', $wrapped);
    }
    protected function wrapValue($value)
    {
        if ($value === '*') {
            return $value;
        }
        return '"' . str_replace('"', '""', $value) . '"';
    }
    public function columnize(array $columns)
    {
        return implode(', ', array_map([$this, 'wrap'], $columns));
    }
    public function parameterize(array $values)
    {
        return implode(', ', array_map([$this, 'parameter'], $values));
    }
    public function parameter($value)
    {
        return $this->isExpression($value) ? $this->getValue($value) : '?';
    }
    public function getValue($expression)
    {
        return $expression->getValue();
    }
    public function isExpression($value)
    {
        return $value instanceof Expression;
    }
    public function getDateFormat()
    {
        return 'Y-m-d H:i:s';
    }
    public function getTablePrefix()
    {
        return $this->tablePrefix;
    }
    public function setTablePrefix($prefix)
    {
        $this->tablePrefix = $prefix;
        return $this;
    }
}
}

namespace Illuminate\Database {
use PDO;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Illuminate\Database\Connectors\ConnectionFactory;
class DatabaseManager implements ConnectionResolverInterface
{
    protected $app;
    protected $factory;
    protected $connections = [];
    protected $extensions = [];
    public function __construct($app, ConnectionFactory $factory)
    {
        $this->app = $app;
        $this->factory = $factory;
    }
    public function connection($name = null)
    {
        list($name, $type) = $this->parseConnectionName($name);
        if (!isset($this->connections[$name])) {
            $connection = $this->makeConnection($name);
            $this->setPdoForType($connection, $type);
            $this->connections[$name] = $this->prepare($connection);
        }
        return $this->connections[$name];
    }
    protected function parseConnectionName($name)
    {
        $name = $name ?: $this->getDefaultConnection();
        return Str::endsWith($name, ['::read', '::write']) ? explode('::', $name, 2) : [$name, null];
    }
    public function purge($name = null)
    {
        $this->disconnect($name);
        unset($this->connections[$name]);
    }
    public function disconnect($name = null)
    {
        if (isset($this->connections[$name = $name ?: $this->getDefaultConnection()])) {
            $this->connections[$name]->disconnect();
        }
    }
    public function reconnect($name = null)
    {
        $this->disconnect($name = $name ?: $this->getDefaultConnection());
        if (!isset($this->connections[$name])) {
            return $this->connection($name);
        }
        return $this->refreshPdoConnections($name);
    }
    protected function refreshPdoConnections($name)
    {
        $fresh = $this->makeConnection($name);
        return $this->connections[$name]->setPdo($fresh->getPdo())->setReadPdo($fresh->getReadPdo());
    }
    protected function makeConnection($name)
    {
        $config = $this->getConfig($name);
        if (isset($this->extensions[$name])) {
            return call_user_func($this->extensions[$name], $config, $name);
        }
        $driver = $config['driver'];
        if (isset($this->extensions[$driver])) {
            return call_user_func($this->extensions[$driver], $config, $name);
        }
        return $this->factory->make($config, $name);
    }
    protected function prepare(Connection $connection)
    {
        $connection->setFetchMode($this->app['config']['database.fetch']);
        if ($this->app->bound('events')) {
            $connection->setEventDispatcher($this->app['events']);
        }
        $connection->setReconnector(function ($connection) {
            $this->reconnect($connection->getName());
        });
        return $connection;
    }
    protected function setPdoForType(Connection $connection, $type = null)
    {
        if ($type == 'read') {
            $connection->setPdo($connection->getReadPdo());
        } elseif ($type == 'write') {
            $connection->setReadPdo($connection->getPdo());
        }
        return $connection;
    }
    protected function getConfig($name)
    {
        $name = $name ?: $this->getDefaultConnection();
        $connections = $this->app['config']['database.connections'];
        if (is_null($config = Arr::get($connections, $name))) {
            throw new InvalidArgumentException("Database [{$name}] not configured.");
        }
        return $config;
    }
    public function getDefaultConnection()
    {
        return $this->app['config']['database.default'];
    }
    public function setDefaultConnection($name)
    {
        $this->app['config']['database.default'] = $name;
    }
    public function supportedDrivers()
    {
        return ['mysql', 'pgsql', 'sqlite', 'sqlsrv'];
    }
    public function availableDrivers()
    {
        return array_intersect($this->supportedDrivers(), str_replace('dblib', 'sqlsrv', PDO::getAvailableDrivers()));
    }
    public function extend($name, callable $resolver)
    {
        $this->extensions[$name] = $resolver;
    }
    public function getConnections()
    {
        return $this->connections;
    }
    public function __call($method, $parameters)
    {
        return $this->connection()->{$method}(...$parameters);
    }
}
}

namespace Illuminate\Database {
use Illuminate\Database\Schema\PostgresBuilder;
use Doctrine\DBAL\Driver\PDOPgSql\Driver as DoctrineDriver;
use Illuminate\Database\Query\Processors\PostgresProcessor;
use Illuminate\Database\Query\Grammars\PostgresGrammar as QueryGrammar;
use Illuminate\Database\Schema\Grammars\PostgresGrammar as SchemaGrammar;
class PostgresConnection extends Connection
{
    public function getSchemaBuilder()
    {
        if (is_null($this->schemaGrammar)) {
            $this->useDefaultSchemaGrammar();
        }
        return new PostgresBuilder($this);
    }
    protected function getDefaultQueryGrammar()
    {
        return $this->withTablePrefix(new QueryGrammar());
    }
    protected function getDefaultSchemaGrammar()
    {
        return $this->withTablePrefix(new SchemaGrammar());
    }
    protected function getDefaultPostProcessor()
    {
        return new PostgresProcessor();
    }
    protected function getDoctrineDriver()
    {
        return new DoctrineDriver();
    }
}
}

namespace Illuminate\Database\Query\Grammars {
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\JoinClause;
use Illuminate\Database\Grammar as BaseGrammar;
class Grammar extends BaseGrammar
{
    protected $operators = [];
    protected $selectComponents = ['aggregate', 'columns', 'from', 'joins', 'wheres', 'groups', 'havings', 'orders', 'limit', 'offset', 'unions', 'lock'];
    public function compileSelect(Builder $query)
    {
        $original = $query->columns;
        if (is_null($query->columns)) {
            $query->columns = ['*'];
        }
        $sql = trim($this->concatenate($this->compileComponents($query)));
        $query->columns = $original;
        return $sql;
    }
    protected function compileComponents(Builder $query)
    {
        $sql = [];
        foreach ($this->selectComponents as $component) {
            if (!is_null($query->{$component})) {
                $method = 'compile' . ucfirst($component);
                $sql[$component] = $this->{$method}($query, $query->{$component});
            }
        }
        return $sql;
    }
    protected function compileAggregate(Builder $query, $aggregate)
    {
        $column = $this->columnize($aggregate['columns']);
        if ($query->distinct && $column !== '*') {
            $column = 'distinct ' . $column;
        }
        return 'select ' . $aggregate['function'] . '(' . $column . ') as aggregate';
    }
    protected function compileColumns(Builder $query, $columns)
    {
        if (!is_null($query->aggregate)) {
            return;
        }
        $select = $query->distinct ? 'select distinct ' : 'select ';
        return $select . $this->columnize($columns);
    }
    protected function compileFrom(Builder $query, $table)
    {
        return 'from ' . $this->wrapTable($table);
    }
    protected function compileJoins(Builder $query, $joins)
    {
        $sql = [];
        foreach ($joins as $join) {
            $conditions = $this->compileWheres($join);
            $table = $this->wrapTable($join->table);
            $sql[] = trim("{$join->type} join {$table} {$conditions}");
        }
        return implode(' ', $sql);
    }
    protected function compileWheres(Builder $query)
    {
        $sql = [];
        if (is_null($query->wheres)) {
            return '';
        }
        foreach ($query->wheres as $where) {
            $method = "where{$where['type']}";
            $sql[] = $where['boolean'] . ' ' . $this->{$method}($query, $where);
        }
        if (count($sql) > 0) {
            $sql = implode(' ', $sql);
            $conjunction = $query instanceof JoinClause ? 'on' : 'where';
            return $conjunction . ' ' . $this->removeLeadingBoolean($sql);
        }
        return '';
    }
    protected function whereNested(Builder $query, $where)
    {
        $nested = $where['query'];
        $offset = $query instanceof JoinClause ? 3 : 6;
        return '(' . substr($this->compileWheres($nested), $offset) . ')';
    }
    protected function whereSub(Builder $query, $where)
    {
        $select = $this->compileSelect($where['query']);
        return $this->wrap($where['column']) . ' ' . $where['operator'] . " ({$select})";
    }
    protected function whereBasic(Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return $this->wrap($where['column']) . ' ' . $where['operator'] . ' ' . $value;
    }
    protected function whereColumn(Builder $query, $where)
    {
        $second = $this->wrap($where['second']);
        return $this->wrap($where['first']) . ' ' . $where['operator'] . ' ' . $second;
    }
    protected function whereBetween(Builder $query, $where)
    {
        $between = $where['not'] ? 'not between' : 'between';
        return $this->wrap($where['column']) . ' ' . $between . ' ? and ?';
    }
    protected function whereExists(Builder $query, $where)
    {
        return 'exists (' . $this->compileSelect($where['query']) . ')';
    }
    protected function whereNotExists(Builder $query, $where)
    {
        return 'not exists (' . $this->compileSelect($where['query']) . ')';
    }
    protected function whereIn(Builder $query, $where)
    {
        if (empty($where['values'])) {
            return '0 = 1';
        }
        $values = $this->parameterize($where['values']);
        return $this->wrap($where['column']) . ' in (' . $values . ')';
    }
    protected function whereNotIn(Builder $query, $where)
    {
        if (empty($where['values'])) {
            return '1 = 1';
        }
        $values = $this->parameterize($where['values']);
        return $this->wrap($where['column']) . ' not in (' . $values . ')';
    }
    protected function whereInSub(Builder $query, $where)
    {
        $select = $this->compileSelect($where['query']);
        return $this->wrap($where['column']) . ' in (' . $select . ')';
    }
    protected function whereNotInSub(Builder $query, $where)
    {
        $select = $this->compileSelect($where['query']);
        return $this->wrap($where['column']) . ' not in (' . $select . ')';
    }
    protected function whereNull(Builder $query, $where)
    {
        return $this->wrap($where['column']) . ' is null';
    }
    protected function whereNotNull(Builder $query, $where)
    {
        return $this->wrap($where['column']) . ' is not null';
    }
    protected function whereDate(Builder $query, $where)
    {
        return $this->dateBasedWhere('date', $query, $where);
    }
    protected function whereTime(Builder $query, $where)
    {
        return $this->dateBasedWhere('time', $query, $where);
    }
    protected function whereDay(Builder $query, $where)
    {
        return $this->dateBasedWhere('day', $query, $where);
    }
    protected function whereMonth(Builder $query, $where)
    {
        return $this->dateBasedWhere('month', $query, $where);
    }
    protected function whereYear(Builder $query, $where)
    {
        return $this->dateBasedWhere('year', $query, $where);
    }
    protected function dateBasedWhere($type, Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return $type . '(' . $this->wrap($where['column']) . ') ' . $where['operator'] . ' ' . $value;
    }
    protected function whereRaw(Builder $query, $where)
    {
        return $where['sql'];
    }
    protected function compileGroups(Builder $query, $groups)
    {
        return 'group by ' . $this->columnize($groups);
    }
    protected function compileHavings(Builder $query, $havings)
    {
        $sql = implode(' ', array_map([$this, 'compileHaving'], $havings));
        return 'having ' . $this->removeLeadingBoolean($sql);
    }
    protected function compileHaving(array $having)
    {
        if ($having['type'] === 'raw') {
            return $having['boolean'] . ' ' . $having['sql'];
        }
        return $this->compileBasicHaving($having);
    }
    protected function compileBasicHaving($having)
    {
        $column = $this->wrap($having['column']);
        $parameter = $this->parameter($having['value']);
        return $having['boolean'] . ' ' . $column . ' ' . $having['operator'] . ' ' . $parameter;
    }
    protected function compileOrders(Builder $query, $orders)
    {
        return 'order by ' . implode(', ', array_map(function ($order) {
            if (isset($order['sql'])) {
                return $order['sql'];
            }
            return $this->wrap($order['column']) . ' ' . $order['direction'];
        }, $orders));
    }
    public function compileRandom($seed)
    {
        return 'RANDOM()';
    }
    protected function compileLimit(Builder $query, $limit)
    {
        return 'limit ' . (int) $limit;
    }
    protected function compileOffset(Builder $query, $offset)
    {
        return 'offset ' . (int) $offset;
    }
    protected function compileUnions(Builder $query)
    {
        $sql = '';
        foreach ($query->unions as $union) {
            $sql .= $this->compileUnion($union);
        }
        if (isset($query->unionOrders)) {
            $sql .= ' ' . $this->compileOrders($query, $query->unionOrders);
        }
        if (isset($query->unionLimit)) {
            $sql .= ' ' . $this->compileLimit($query, $query->unionLimit);
        }
        if (isset($query->unionOffset)) {
            $sql .= ' ' . $this->compileOffset($query, $query->unionOffset);
        }
        return ltrim($sql);
    }
    protected function compileUnion(array $union)
    {
        $joiner = $union['all'] ? ' union all ' : ' union ';
        return $joiner . $union['query']->toSql();
    }
    public function compileExists(Builder $query)
    {
        $select = $this->compileSelect($query);
        return "select exists({$select}) as {$this->wrap('exists')}";
    }
    public function compileInsert(Builder $query, array $values)
    {
        $table = $this->wrapTable($query->from);
        if (!is_array(reset($values))) {
            $values = [$values];
        }
        $columns = $this->columnize(array_keys(reset($values)));
        $parameters = [];
        foreach ($values as $record) {
            $parameters[] = '(' . $this->parameterize($record) . ')';
        }
        $parameters = implode(', ', $parameters);
        return "insert into {$table} ({$columns}) values {$parameters}";
    }
    public function compileInsertGetId(Builder $query, $values, $sequence)
    {
        return $this->compileInsert($query, $values);
    }
    public function compileUpdate(Builder $query, $values)
    {
        $table = $this->wrapTable($query->from);
        $columns = [];
        foreach ($values as $key => $value) {
            $columns[] = $this->wrap($key) . ' = ' . $this->parameter($value);
        }
        $columns = implode(', ', $columns);
        if (isset($query->joins)) {
            $joins = ' ' . $this->compileJoins($query, $query->joins);
        } else {
            $joins = '';
        }
        $where = $this->compileWheres($query);
        return trim("update {$table}{$joins} set {$columns} {$where}");
    }
    public function prepareBindingsForUpdate(array $bindings, array $values)
    {
        return $bindings;
    }
    public function compileDelete(Builder $query)
    {
        $table = $this->wrapTable($query->from);
        $where = is_array($query->wheres) ? $this->compileWheres($query) : '';
        return trim("delete from {$table} " . $where);
    }
    public function compileTruncate(Builder $query)
    {
        return ['truncate ' . $this->wrapTable($query->from) => []];
    }
    protected function compileLock(Builder $query, $value)
    {
        return is_string($value) ? $value : '';
    }
    public function supportsSavepoints()
    {
        return true;
    }
    public function compileSavepoint($name)
    {
        return 'SAVEPOINT ' . $name;
    }
    public function compileSavepointRollBack($name)
    {
        return 'ROLLBACK TO SAVEPOINT ' . $name;
    }
    protected function concatenate($segments)
    {
        return implode(' ', array_filter($segments, function ($value) {
            return (string) $value !== '';
        }));
    }
    protected function removeLeadingBoolean($value)
    {
        return preg_replace('/and |or /i', '', $value, 1);
    }
    public function getOperators()
    {
        return $this->operators;
    }
}
}

namespace Illuminate\Database\Query\Grammars {
use Illuminate\Database\Query\Builder;
class SqlServerGrammar extends Grammar
{
    protected $operators = ['=', '<', '>', '<=', '>=', '!<', '!>', '<>', '!=', 'like', 'not like', 'between', 'ilike', '&', '&=', '|', '|=', '^', '^='];
    public function compileSelect(Builder $query)
    {
        $original = $query->columns;
        if (is_null($query->columns)) {
            $query->columns = ['*'];
        }
        $components = $this->compileComponents($query);
        if ($query->offset > 0) {
            return $this->compileAnsiOffset($query, $components);
        }
        $sql = $this->concatenate($components);
        $query->columns = $original;
        return $sql;
    }
    protected function compileColumns(Builder $query, $columns)
    {
        if (!is_null($query->aggregate)) {
            return;
        }
        $select = $query->distinct ? 'select distinct ' : 'select ';
        if ($query->limit > 0 && $query->offset <= 0) {
            $select .= 'top ' . $query->limit . ' ';
        }
        return $select . $this->columnize($columns);
    }
    protected function compileFrom(Builder $query, $table)
    {
        $from = parent::compileFrom($query, $table);
        if (is_string($query->lock)) {
            return $from . ' ' . $query->lock;
        }
        if (!is_null($query->lock)) {
            return $from . ' with(rowlock,' . ($query->lock ? 'updlock,' : '') . 'holdlock)';
        }
        return $from;
    }
    protected function compileAnsiOffset(Builder $query, $components)
    {
        if (!isset($components['orders'])) {
            $components['orders'] = 'order by (select 0)';
        }
        $orderings = $components['orders'];
        $components['columns'] .= $this->compileOver($orderings);
        unset($components['orders']);
        $constraint = $this->compileRowConstraint($query);
        $sql = $this->concatenate($components);
        return $this->compileTableExpression($sql, $constraint);
    }
    protected function compileOver($orderings)
    {
        return ", row_number() over ({$orderings}) as row_num";
    }
    protected function compileRowConstraint($query)
    {
        $start = $query->offset + 1;
        if ($query->limit > 0) {
            $finish = $query->offset + $query->limit;
            return "between {$start} and {$finish}";
        }
        return ">= {$start}";
    }
    protected function compileTableExpression($sql, $constraint)
    {
        return "select * from ({$sql}) as temp_table where row_num {$constraint}";
    }
    public function compileRandom($seed)
    {
        return 'NEWID()';
    }
    protected function compileLimit(Builder $query, $limit)
    {
        return '';
    }
    protected function compileOffset(Builder $query, $offset)
    {
        return '';
    }
    public function compileTruncate(Builder $query)
    {
        return ['truncate table ' . $this->wrapTable($query->from) => []];
    }
    public function compileExists(Builder $query)
    {
        $existsQuery = clone $query;
        $existsQuery->columns = [];
        return $this->compileSelect($existsQuery->selectRaw('1 [exists]')->limit(1));
    }
    protected function whereDate(Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return 'cast(' . $this->wrap($where['column']) . ' as date) ' . $where['operator'] . ' ' . $value;
    }
    public function supportsSavepoints()
    {
        return false;
    }
    public function getDateFormat()
    {
        return 'Y-m-d H:i:s.000';
    }
    protected function wrapValue($value)
    {
        if ($value === '*') {
            return $value;
        }
        return '[' . str_replace(']', ']]', $value) . ']';
    }
    public function compileUpdate(Builder $query, $values)
    {
        $table = $alias = $this->wrapTable($query->from);
        if (strpos(strtolower($table), '] as [') !== false) {
            $segments = explode('] as [', $table);
            $alias = '[' . $segments[1];
        }
        $columns = [];
        foreach ($values as $key => $value) {
            $columns[] = $this->wrap($key) . ' = ' . $this->parameter($value);
        }
        $columns = implode(', ', $columns);
        if (isset($query->joins)) {
            $joins = ' ' . $this->compileJoins($query, $query->joins);
        } else {
            $joins = '';
        }
        $where = $this->compileWheres($query);
        if (!empty($joins)) {
            return trim("update {$alias} set {$columns} from {$table}{$joins} {$where}");
        }
        return trim("update {$table}{$joins} set {$columns} {$where}");
    }
    public function wrapTable($table)
    {
        return $this->wrapTableValuedFunction(parent::wrapTable($table));
    }
    protected function wrapTableValuedFunction($table)
    {
        if (preg_match('/^(.+?)(\\(.*?\\))]$/', $table, $matches) === 1) {
            $table = $matches[1] . ']' . $matches[2];
        }
        return $table;
    }
}
}

namespace Illuminate\Database\Query\Grammars {
use Illuminate\Support\Str;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\JsonExpression;
class MySqlGrammar extends Grammar
{
    protected $selectComponents = ['aggregate', 'columns', 'from', 'joins', 'wheres', 'groups', 'havings', 'orders', 'limit', 'offset', 'lock'];
    public function compileSelect(Builder $query)
    {
        $sql = parent::compileSelect($query);
        if ($query->unions) {
            $sql = '(' . $sql . ') ' . $this->compileUnions($query);
        }
        return $sql;
    }
    protected function compileUnion(array $union)
    {
        $joiner = $union['all'] ? ' union all ' : ' union ';
        return $joiner . '(' . $union['query']->toSql() . ')';
    }
    public function compileRandom($seed)
    {
        return 'RAND(' . $seed . ')';
    }
    protected function compileLock(Builder $query, $value)
    {
        if (is_string($value)) {
            return $value;
        }
        return $value ? 'for update' : 'lock in share mode';
    }
    public function compileUpdate(Builder $query, $values)
    {
        $table = $this->wrapTable($query->from);
        $columns = [];
        foreach ($values as $key => $value) {
            if ($this->isJsonSelector($key)) {
                $columns[] = $this->compileJsonUpdateColumn($key, new JsonExpression($value));
            } else {
                $columns[] = $this->wrap($key) . ' = ' . $this->parameter($value);
            }
        }
        $columns = implode(', ', $columns);
        if (isset($query->joins)) {
            $joins = ' ' . $this->compileJoins($query, $query->joins);
        } else {
            $joins = '';
        }
        $where = $this->compileWheres($query);
        $sql = rtrim("update {$table}{$joins} set {$columns} {$where}");
        if (isset($query->orders)) {
            $sql .= ' ' . $this->compileOrders($query, $query->orders);
        }
        if (isset($query->limit)) {
            $sql .= ' ' . $this->compileLimit($query, $query->limit);
        }
        return rtrim($sql);
    }
    protected function compileJsonUpdateColumn($key, JsonExpression $value)
    {
        $path = explode('->', $key);
        $field = $this->wrapValue(array_shift($path));
        $accessor = '"$.' . implode('.', $path) . '"';
        return "{$field} = json_set({$field}, {$accessor}, {$value->getValue()})";
    }
    public function prepareBindingsForUpdate(array $bindings, array $values)
    {
        $index = 0;
        foreach ($values as $column => $value) {
            if ($this->isJsonSelector($column) && is_bool($value)) {
                unset($bindings[$index]);
            }
            $index++;
        }
        return $bindings;
    }
    public function compileDelete(Builder $query)
    {
        $table = $this->wrapTable($query->from);
        $where = is_array($query->wheres) ? $this->compileWheres($query) : '';
        if (isset($query->joins)) {
            $joins = ' ' . $this->compileJoins($query, $query->joins);
            $sql = trim("delete {$table} from {$table}{$joins} {$where}");
        } else {
            $sql = trim("delete from {$table} {$where}");
            if (isset($query->orders)) {
                $sql .= ' ' . $this->compileOrders($query, $query->orders);
            }
            if (isset($query->limit)) {
                $sql .= ' ' . $this->compileLimit($query, $query->limit);
            }
        }
        return $sql;
    }
    protected function wrapValue($value)
    {
        if ($value === '*') {
            return $value;
        }
        if ($this->isJsonSelector($value)) {
            return $this->wrapJsonSelector($value);
        }
        return '`' . str_replace('`', '``', $value) . '`';
    }
    protected function wrapJsonSelector($value)
    {
        $path = explode('->', $value);
        $field = $this->wrapValue(array_shift($path));
        return $field . '->' . '"$.' . implode('.', $path) . '"';
    }
    protected function isJsonSelector($value)
    {
        return Str::contains($value, '->');
    }
}
}

namespace Illuminate\Database\Query\Grammars {
use Illuminate\Support\Str;
use Illuminate\Database\Query\Builder;
class PostgresGrammar extends Grammar
{
    protected $operators = ['=', '<', '>', '<=', '>=', '<>', '!=', 'like', 'not like', 'between', 'ilike', '&', '|', '#', '<<', '>>', '@>', '<@', '?', '?|', '?&', '||', '-', '-', '#-'];
    protected function compileLock(Builder $query, $value)
    {
        if (is_string($value)) {
            return $value;
        }
        return $value ? 'for update' : 'for share';
    }
    protected function whereDate(Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return $this->wrap($where['column']) . '::date ' . $where['operator'] . ' ' . $value;
    }
    protected function dateBasedWhere($type, Builder $query, $where)
    {
        $value = $this->parameter($where['value']);
        return 'extract(' . $type . ' from ' . $this->wrap($where['column']) . ') ' . $where['operator'] . ' ' . $value;
    }
    public function compileUpdate(Builder $query, $values)
    {
        $table = $this->wrapTable($query->from);
        $columns = $this->compileUpdateColumns($values);
        $from = $this->compileUpdateFrom($query);
        $where = $this->compileUpdateWheres($query);
        return trim("update {$table} set {$columns}{$from} {$where}");
    }
    protected function compileUpdateColumns($values)
    {
        $columns = [];
        foreach ($values as $key => $value) {
            $columns[] = $this->wrap($key) . ' = ' . $this->parameter($value);
        }
        return implode(', ', $columns);
    }
    protected function compileUpdateFrom(Builder $query)
    {
        if (!isset($query->joins)) {
            return '';
        }
        $froms = [];
        foreach ($query->joins as $join) {
            $froms[] = $this->wrapTable($join->table);
        }
        if (count($froms) > 0) {
            return ' from ' . implode(', ', $froms);
        }
    }
    protected function compileUpdateWheres(Builder $query)
    {
        $baseWhere = $this->compileWheres($query);
        if (!isset($query->joins)) {
            return $baseWhere;
        }
        $joinWhere = $this->compileUpdateJoinWheres($query);
        if (trim($baseWhere) == '') {
            return 'where ' . $this->removeLeadingBoolean($joinWhere);
        }
        return $baseWhere . ' ' . $joinWhere;
    }
    protected function compileUpdateJoinWheres(Builder $query)
    {
        $joinWheres = [];
        foreach ($query->joins as $join) {
            foreach ($join->wheres as $where) {
                $method = "where{$where['type']}";
                $joinWheres[] = $where['boolean'] . ' ' . $this->{$method}($query, $where);
            }
        }
        return implode(' ', $joinWheres);
    }
    public function compileInsertGetId(Builder $query, $values, $sequence)
    {
        if (is_null($sequence)) {
            $sequence = 'id';
        }
        return $this->compileInsert($query, $values) . ' returning ' . $this->wrap($sequence);
    }
    public function compileTruncate(Builder $query)
    {
        return ['truncate ' . $this->wrapTable($query->from) . ' restart identity' => []];
    }
    protected function wrapValue($value)
    {
        if ($value === '*') {
            return $value;
        }
        if (Str::contains($value, '->')) {
            return $this->wrapJsonSelector($value);
        }
        return '"' . str_replace('"', '""', $value) . '"';
    }
    protected function wrapJsonSelector($value)
    {
        $path = explode('->', $value);
        $field = $this->wrapValue(array_shift($path));
        $wrappedPath = $this->wrapJsonPathAttributes($path);
        $attribute = array_pop($wrappedPath);
        if (!empty($wrappedPath)) {
            return $field . '->' . implode('->', $wrappedPath) . '->>' . $attribute;
        }
        return $field . '->>' . $attribute;
    }
    protected function wrapJsonPathAttributes($path)
    {
        return array_map(function ($attribute) {
            return "'{$attribute}'";
        }, $path);
    }
}
}

namespace Illuminate\Database\Query\Grammars {
use Illuminate\Database\Query\Builder;
class SQLiteGrammar extends Grammar
{
    protected $operators = ['=', '<', '>', '<=', '>=', '<>', '!=', 'like', 'not like', 'between', 'ilike', '&', '|', '<<', '>>'];
    public function compileInsert(Builder $query, array $values)
    {
        $table = $this->wrapTable($query->from);
        if (!is_array(reset($values))) {
            $values = [$values];
        }
        if (count($values) == 1) {
            return parent::compileInsert($query, reset($values));
        }
        $names = $this->columnize(array_keys(reset($values)));
        $columns = [];
        foreach (array_keys(reset($values)) as $column) {
            $columns[] = '? as ' . $this->wrap($column);
        }
        $columns = array_fill(0, count($values), implode(', ', $columns));
        return "insert into {$table} ({$names}) select " . implode(' union all select ', $columns);
    }
    public function compileTruncate(Builder $query)
    {
        $sql = ['delete from sqlite_sequence where name = ?' => [$query->from]];
        $sql['delete from ' . $this->wrapTable($query->from)] = [];
        return $sql;
    }
    protected function whereDate(Builder $query, $where)
    {
        return $this->dateBasedWhere('%Y-%m-%d', $query, $where);
    }
    protected function whereDay(Builder $query, $where)
    {
        return $this->dateBasedWhere('%d', $query, $where);
    }
    protected function whereMonth(Builder $query, $where)
    {
        return $this->dateBasedWhere('%m', $query, $where);
    }
    protected function whereYear(Builder $query, $where)
    {
        return $this->dateBasedWhere('%Y', $query, $where);
    }
    protected function dateBasedWhere($type, Builder $query, $where)
    {
        $value = str_pad($where['value'], 2, '0', STR_PAD_LEFT);
        $value = $this->parameter($value);
        return 'strftime(\'' . $type . '\', ' . $this->wrap($where['column']) . ') ' . $where['operator'] . ' ' . $value;
    }
}
}

namespace Illuminate\Database\Query {
class Expression
{
    protected $value;
    public function __construct($value)
    {
        $this->value = $value;
    }
    public function getValue()
    {
        return $this->value;
    }
    public function __toString()
    {
        return (string) $this->getValue();
    }
}
}

namespace Illuminate\Database\Query\Processors {
class SQLiteProcessor extends Processor
{
    public function processColumnListing($results)
    {
        $mapping = function ($r) {
            $r = (object) $r;
            return $r->name;
        };
        return array_map($mapping, $results);
    }
}
}

namespace Illuminate\Database\Query\Processors {
use Illuminate\Database\Query\Builder;
class Processor
{
    public function processSelect(Builder $query, $results)
    {
        return $results;
    }
    public function processInsertGetId(Builder $query, $sql, $values, $sequence = null)
    {
        $query->getConnection()->insert($sql, $values);
        $id = $query->getConnection()->getPdo()->lastInsertId($sequence);
        return is_numeric($id) ? (int) $id : $id;
    }
    public function processColumnListing($results)
    {
        return $results;
    }
}
}

namespace Illuminate\Database\Query\Processors {
use Exception;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
class SqlServerProcessor extends Processor
{
    public function processInsertGetId(Builder $query, $sql, $values, $sequence = null)
    {
        $connection = $query->getConnection();
        $connection->insert($sql, $values);
        if ($connection->getConfig('odbc') === true) {
            $id = $this->processInsertGetIdForOdbc($connection);
        } else {
            $id = $connection->getPdo()->lastInsertId();
        }
        return is_numeric($id) ? (int) $id : $id;
    }
    protected function processInsertGetIdForOdbc(Connection $connection)
    {
        $result = $connection->selectFromWriteConnection('SELECT CAST(COALESCE(SCOPE_IDENTITY(), @@IDENTITY) AS int) AS insertid');
        if (!$result) {
            throw new Exception('Unable to retrieve lastInsertID for ODBC.');
        }
        $row = $result[0];
        return is_object($row) ? $row->insertid : $row['insertid'];
    }
    public function processColumnListing($results)
    {
        $mapping = function ($r) {
            $r = (object) $r;
            return $r->name;
        };
        return array_map($mapping, $results);
    }
}
}

namespace Illuminate\Database\Query\Processors {
use Illuminate\Database\Query\Builder;
class PostgresProcessor extends Processor
{
    public function processInsertGetId(Builder $query, $sql, $values, $sequence = null)
    {
        $result = $query->getConnection()->selectFromWriteConnection($sql, $values)[0];
        $sequence = $sequence ?: 'id';
        $id = is_object($result) ? $result->{$sequence} : $result[$sequence];
        return is_numeric($id) ? (int) $id : $id;
    }
    public function processColumnListing($results)
    {
        $mapping = function ($r) {
            $r = (object) $r;
            return $r->column_name;
        };
        return array_map($mapping, $results);
    }
}
}

namespace Illuminate\Database\Query\Processors {
class MySqlProcessor extends Processor
{
    public function processColumnListing($results)
    {
        $mapping = function ($r) {
            $r = (object) $r;
            return $r->column_name;
        };
        return array_map($mapping, $results);
    }
}
}

namespace Illuminate\Database\Query {
use Closure;
class JoinClause extends Builder
{
    public $type;
    public $table;
    private $parentQuery;
    public function __construct(Builder $parentQuery, $type, $table)
    {
        $this->type = $type;
        $this->table = $table;
        $this->parentQuery = $parentQuery;
        parent::__construct($parentQuery->getConnection(), $parentQuery->getGrammar(), $parentQuery->getProcessor());
    }
    public function on($first, $operator = null, $second = null, $boolean = 'and')
    {
        if ($first instanceof Closure) {
            return $this->whereNested($first, $boolean);
        }
        return $this->whereColumn($first, $operator, $second, $boolean);
    }
    public function orOn($first, $operator = null, $second = null)
    {
        return $this->on($first, $operator, $second, 'or');
    }
    public function newQuery()
    {
        return new static($this->parentQuery, $this->type, $this->table);
    }
}
}

namespace Illuminate\Database {
use Closure;
interface ConnectionInterface
{
    public function table($table);
    public function raw($value);
    public function selectOne($query, $bindings = []);
    public function select($query, $bindings = []);
    public function insert($query, $bindings = []);
    public function update($query, $bindings = []);
    public function delete($query, $bindings = []);
    public function statement($query, $bindings = []);
    public function affectingStatement($query, $bindings = []);
    public function unprepared($query);
    public function prepareBindings(array $bindings);
    public function transaction(Closure $callback, $attempts = 1);
    public function beginTransaction();
    public function commit();
    public function rollBack();
    public function transactionLevel();
    public function pretend(Closure $callback);
}
}

namespace Illuminate\Database {
use Illuminate\Database\Query\Processors\SQLiteProcessor;
use Doctrine\DBAL\Driver\PDOSqlite\Driver as DoctrineDriver;
use Illuminate\Database\Query\Grammars\SQLiteGrammar as QueryGrammar;
use Illuminate\Database\Schema\Grammars\SQLiteGrammar as SchemaGrammar;
class SQLiteConnection extends Connection
{
    protected function getDefaultQueryGrammar()
    {
        return $this->withTablePrefix(new QueryGrammar());
    }
    protected function getDefaultSchemaGrammar()
    {
        return $this->withTablePrefix(new SchemaGrammar());
    }
    protected function getDefaultPostProcessor()
    {
        return new SQLiteProcessor();
    }
    protected function getDoctrineDriver()
    {
        return new DoctrineDriver();
    }
}
}

namespace Illuminate\Database\Connectors {
use PDO;
use Illuminate\Support\Arr;
use InvalidArgumentException;
use Illuminate\Database\MySqlConnection;
use Illuminate\Database\SQLiteConnection;
use Illuminate\Database\PostgresConnection;
use Illuminate\Database\SqlServerConnection;
use Illuminate\Contracts\Container\Container;
class ConnectionFactory
{
    protected $container;
    public function __construct(Container $container)
    {
        $this->container = $container;
    }
    public function make(array $config, $name = null)
    {
        $config = $this->parseConfig($config, $name);
        if (isset($config['read'])) {
            return $this->createReadWriteConnection($config);
        }
        return $this->createSingleConnection($config);
    }
    protected function createSingleConnection(array $config)
    {
        $pdo = $this->createPdoResolver($config);
        return $this->createConnection($config['driver'], $pdo, $config['database'], $config['prefix'], $config);
    }
    protected function createReadWriteConnection(array $config)
    {
        $connection = $this->createSingleConnection($this->getWriteConfig($config));
        return $connection->setReadPdo($this->createReadPdo($config));
    }
    protected function createReadPdo(array $config)
    {
        return $this->createPdoResolver($this->getReadConfig($config));
    }
    protected function createPdoResolver(array $config)
    {
        return function () use($config) {
            return $this->createConnector($config)->connect($config);
        };
    }
    protected function getReadConfig(array $config)
    {
        $readConfig = $this->getReadWriteConfig($config, 'read');
        if (isset($readConfig['host']) && is_array($readConfig['host'])) {
            $readConfig['host'] = count($readConfig['host']) > 1 ? $readConfig['host'][array_rand($readConfig['host'])] : $readConfig['host'][0];
        }
        return $this->mergeReadWriteConfig($config, $readConfig);
    }
    protected function getWriteConfig(array $config)
    {
        $writeConfig = $this->getReadWriteConfig($config, 'write');
        return $this->mergeReadWriteConfig($config, $writeConfig);
    }
    protected function getReadWriteConfig(array $config, $type)
    {
        if (isset($config[$type][0])) {
            return $config[$type][array_rand($config[$type])];
        }
        return $config[$type];
    }
    protected function mergeReadWriteConfig(array $config, array $merge)
    {
        return Arr::except(array_merge($config, $merge), ['read', 'write']);
    }
    protected function parseConfig(array $config, $name)
    {
        return Arr::add(Arr::add($config, 'prefix', ''), 'name', $name);
    }
    public function createConnector(array $config)
    {
        if (!isset($config['driver'])) {
            throw new InvalidArgumentException('A driver must be specified.');
        }
        if ($this->container->bound($key = "db.connector.{$config['driver']}")) {
            return $this->container->make($key);
        }
        switch ($config['driver']) {
            case 'mysql':
                return new MySqlConnector();
            case 'pgsql':
                return new PostgresConnector();
            case 'sqlite':
                return new SQLiteConnector();
            case 'sqlsrv':
                return new SqlServerConnector();
        }
        throw new InvalidArgumentException("Unsupported driver [{$config['driver']}]");
    }
    protected function createConnection($driver, $connection, $database, $prefix = '', array $config = [])
    {
        if ($this->container->bound($key = "db.connection.{$driver}")) {
            return $this->container->make($key, [$connection, $database, $prefix, $config]);
        }
        switch ($driver) {
            case 'mysql':
                return new MySqlConnection($connection, $database, $prefix, $config);
            case 'pgsql':
                return new PostgresConnection($connection, $database, $prefix, $config);
            case 'sqlite':
                return new SQLiteConnection($connection, $database, $prefix, $config);
            case 'sqlsrv':
                return new SqlServerConnection($connection, $database, $prefix, $config);
        }
        throw new InvalidArgumentException("Unsupported driver [{$driver}]");
    }
}
}

namespace Illuminate\Database\Connectors {
use PDO;
use Illuminate\Support\Arr;
class SqlServerConnector extends Connector implements ConnectorInterface
{
    protected $options = [PDO::ATTR_CASE => PDO::CASE_NATURAL, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_ORACLE_NULLS => PDO::NULL_NATURAL, PDO::ATTR_STRINGIFY_FETCHES => false];
    public function connect(array $config)
    {
        $options = $this->getOptions($config);
        return $this->createConnection($this->getDsn($config), $config, $options);
    }
    protected function getDsn(array $config)
    {
        if (in_array('dblib', $this->getAvailableDrivers())) {
            return $this->getDblibDsn($config);
        } elseif ($this->prefersOdbc($config)) {
            return $this->getOdbcDsn($config);
        } else {
            return $this->getSqlSrvDsn($config);
        }
    }
    protected function getDblibDsn(array $config)
    {
        $arguments = ['host' => $this->buildHostString($config, ':'), 'dbname' => $config['database']];
        $arguments = array_merge($arguments, Arr::only($config, ['appname', 'charset']));
        return $this->buildConnectString('dblib', $arguments);
    }
    protected function prefersOdbc(array $config)
    {
        return in_array('odbc', $this->getAvailableDrivers()) && array_get($config, 'odbc') === true;
    }
    protected function getOdbcDsn(array $config)
    {
        if (isset($config['odbc_datasource_name'])) {
            return 'odbc:' . $config['odbc_datasource_name'];
        }
        return '';
    }
    protected function getSqlSrvDsn(array $config)
    {
        $arguments = ['Server' => $this->buildHostString($config, ',')];
        if (isset($config['database'])) {
            $arguments['Database'] = $config['database'];
        }
        if (isset($config['appname'])) {
            $arguments['APP'] = $config['appname'];
        }
        if (isset($config['readonly'])) {
            $arguments['ApplicationIntent'] = 'ReadOnly';
        }
        if (isset($config['pooling']) && $config['pooling'] === false) {
            $arguments['ConnectionPooling'] = '0';
        }
        return $this->buildConnectString('sqlsrv', $arguments);
    }
    protected function buildConnectString($driver, array $arguments)
    {
        $options = array_map(function ($key) use($arguments) {
            return sprintf('%s=%s', $key, $arguments[$key]);
        }, array_keys($arguments));
        return $driver . ':' . implode(';', $options);
    }
    protected function buildHostString(array $config, $separator)
    {
        if (isset($config['port'])) {
            return $config['host'] . $separator . $config['port'];
        } else {
            return $config['host'];
        }
    }
    protected function getAvailableDrivers()
    {
        return PDO::getAvailableDrivers();
    }
}
}

namespace Illuminate\Database\Connectors {
use PDO;
class PostgresConnector extends Connector implements ConnectorInterface
{
    protected $options = [PDO::ATTR_CASE => PDO::CASE_NATURAL, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_ORACLE_NULLS => PDO::NULL_NATURAL, PDO::ATTR_STRINGIFY_FETCHES => false];
    public function connect(array $config)
    {
        $dsn = $this->getDsn($config);
        $options = $this->getOptions($config);
        $connection = $this->createConnection($dsn, $config, $options);
        $charset = $config['charset'];
        $connection->prepare("set names '{$charset}'")->execute();
        if (isset($config['timezone'])) {
            $timezone = $config['timezone'];
            $connection->prepare("set time zone '{$timezone}'")->execute();
        }
        if (isset($config['schema'])) {
            $schema = $this->formatSchema($config['schema']);
            $connection->prepare("set search_path to {$schema}")->execute();
        }
        if (isset($config['application_name'])) {
            $applicationName = $config['application_name'];
            $connection->prepare("set application_name to '{$applicationName}'")->execute();
        }
        return $connection;
    }
    protected function getDsn(array $config)
    {
        extract($config, EXTR_SKIP);
        $host = isset($host) ? "host={$host};" : '';
        $dsn = "pgsql:{$host}dbname={$database}";
        if (isset($config['port'])) {
            $dsn .= ";port={$port}";
        }
        if (isset($config['sslmode'])) {
            $dsn .= ";sslmode={$sslmode}";
        }
        if (isset($config['sslcert'])) {
            $dsn .= ";sslcert={$sslcert}";
        }
        if (isset($config['sslkey'])) {
            $dsn .= ";sslkey={$sslkey}";
        }
        if (isset($config['sslrootcert'])) {
            $dsn .= ";sslrootcert={$sslrootcert}";
        }
        return $dsn;
    }
    protected function formatSchema($schema)
    {
        if (is_array($schema)) {
            return '"' . implode('", "', $schema) . '"';
        } else {
            return '"' . $schema . '"';
        }
    }
}
}

namespace Illuminate\Database\Connectors {
interface ConnectorInterface
{
    public function connect(array $config);
}
}

namespace Illuminate\Database\Connectors {
use PDO;
class MySqlConnector extends Connector implements ConnectorInterface
{
    public function connect(array $config)
    {
        $dsn = $this->getDsn($config);
        $options = $this->getOptions($config);
        $connection = $this->createConnection($dsn, $config, $options);
        if (!empty($config['database'])) {
            $connection->exec("use `{$config['database']}`;");
        }
        $collation = $config['collation'];
        if (isset($config['charset'])) {
            $charset = $config['charset'];
            $names = "set names '{$charset}'" . (!is_null($collation) ? " collate '{$collation}'" : '');
            $connection->prepare($names)->execute();
        }
        if (isset($config['timezone'])) {
            $connection->prepare('set time_zone="' . $config['timezone'] . '"')->execute();
        }
        $this->setModes($connection, $config);
        return $connection;
    }
    protected function getDsn(array $config)
    {
        return $this->configHasSocket($config) ? $this->getSocketDsn($config) : $this->getHostDsn($config);
    }
    protected function configHasSocket(array $config)
    {
        return isset($config['unix_socket']) && !empty($config['unix_socket']);
    }
    protected function getSocketDsn(array $config)
    {
        return "mysql:unix_socket={$config['unix_socket']};dbname={$config['database']}";
    }
    protected function getHostDsn(array $config)
    {
        extract($config, EXTR_SKIP);
        return isset($port) ? "mysql:host={$host};port={$port};dbname={$database}" : "mysql:host={$host};dbname={$database}";
    }
    protected function setModes(PDO $connection, array $config)
    {
        if (isset($config['modes'])) {
            $modes = implode(',', $config['modes']);
            $connection->prepare("set session sql_mode='{$modes}'")->execute();
        } elseif (isset($config['strict'])) {
            if ($config['strict']) {
                $connection->prepare("set session sql_mode='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION'")->execute();
            } else {
                $connection->prepare("set session sql_mode='NO_ENGINE_SUBSTITUTION'")->execute();
            }
        }
    }
}
}

namespace Illuminate\Database\Connectors {
use InvalidArgumentException;
class SQLiteConnector extends Connector implements ConnectorInterface
{
    public function connect(array $config)
    {
        $options = $this->getOptions($config);
        if ($config['database'] == ':memory:') {
            return $this->createConnection('sqlite::memory:', $config, $options);
        }
        $path = realpath($config['database']);
        if ($path === false) {
            throw new InvalidArgumentException("Database ({$config['database']}) does not exist.");
        }
        return $this->createConnection("sqlite:{$path}", $config, $options);
    }
}
}

namespace Illuminate\Database {
use Illuminate\Database\Schema\MySqlBuilder;
use Illuminate\Database\Query\Processors\MySqlProcessor;
use Doctrine\DBAL\Driver\PDOMySql\Driver as DoctrineDriver;
use Illuminate\Database\Query\Grammars\MySqlGrammar as QueryGrammar;
use Illuminate\Database\Schema\Grammars\MySqlGrammar as SchemaGrammar;
class MySqlConnection extends Connection
{
    public function getSchemaBuilder()
    {
        if (is_null($this->schemaGrammar)) {
            $this->useDefaultSchemaGrammar();
        }
        return new MySqlBuilder($this);
    }
    protected function getDefaultQueryGrammar()
    {
        return $this->withTablePrefix(new QueryGrammar());
    }
    protected function getDefaultSchemaGrammar()
    {
        return $this->withTablePrefix(new SchemaGrammar());
    }
    protected function getDefaultPostProcessor()
    {
        return new MySqlProcessor();
    }
    protected function getDoctrineDriver()
    {
        return new DoctrineDriver();
    }
}
}

namespace Illuminate\Database {
use Faker\Factory as FakerFactory;
use Faker\Generator as FakerGenerator;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\ServiceProvider;
use Illuminate\Database\Eloquent\QueueEntityResolver;
use Illuminate\Database\Connectors\ConnectionFactory;
use Illuminate\Database\Eloquent\Factory as EloquentFactory;
class DatabaseServiceProvider extends ServiceProvider
{
    public function boot()
    {
        Model::setConnectionResolver($this->app['db']);
        Model::setEventDispatcher($this->app['events']);
    }
    public function register()
    {
        Model::clearBootedModels();
        $this->registerEloquentFactory();
        $this->registerQueueableEntityResolver();
        $this->app->singleton('db.factory', function ($app) {
            return new ConnectionFactory($app);
        });
        $this->app->singleton('db', function ($app) {
            return new DatabaseManager($app, $app['db.factory']);
        });
        $this->app->bind('db.connection', function ($app) {
            return $app['db']->connection();
        });
    }
    protected function registerEloquentFactory()
    {
        $this->app->singleton(FakerGenerator::class, function () {
            return FakerFactory::create();
        });
        $this->app->singleton(EloquentFactory::class, function ($app) {
            $faker = $app->make(FakerGenerator::class);
            return EloquentFactory::construct($faker, database_path('factories'));
        });
    }
    protected function registerQueueableEntityResolver()
    {
        $this->app->singleton('Illuminate\\Contracts\\Queue\\EntityResolver', function () {
            return new QueueEntityResolver();
        });
    }
}
}

namespace Illuminate\Database\Events {
abstract class ConnectionEvent
{
    public $connectionName;
    public $connection;
    public function __construct($connection)
    {
        $this->connection = $connection;
        $this->connectionName = $connection->getName();
    }
}
}

namespace Illuminate\Database\Events {
class TransactionCommitted extends ConnectionEvent
{
}
}

namespace Illuminate\Database\Events {
class TransactionBeginning extends ConnectionEvent
{
}
}

namespace Illuminate\Database\Events {
class TransactionRolledBack extends ConnectionEvent
{
}
}

namespace Illuminate\Database\Events {
class QueryExecuted
{
    public $sql;
    public $bindings;
    public $time;
    public $connection;
    public $connectionName;
    public function __construct($sql, $bindings, $time, $connection)
    {
        $this->sql = $sql;
        $this->time = $time;
        $this->bindings = $bindings;
        $this->connection = $connection;
        $this->connectionName = $connection->getName();
    }
}
}

namespace Illuminate\Database\Migrations {
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Support\Collection;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Database\ConnectionResolverInterface as Resolver;
class Migrator
{
    protected $repository;
    protected $files;
    protected $resolver;
    protected $connection;
    protected $notes = [];
    protected $paths = [];
    public function __construct(MigrationRepositoryInterface $repository, Resolver $resolver, Filesystem $files)
    {
        $this->files = $files;
        $this->resolver = $resolver;
        $this->repository = $repository;
    }
    public function run($paths = [], array $options = [])
    {
        $this->notes = [];
        $files = $this->getMigrationFiles($paths);
        $ran = $this->repository->getRan();
        $migrations = Collection::make($files)->reject(function ($file) use($ran) {
            return in_array($this->getMigrationName($file), $ran);
        })->values()->all();
        $this->requireFiles($migrations);
        $this->runMigrationList($migrations, $options);
        return $migrations;
    }
    public function runMigrationList($migrations, array $options = [])
    {
        if (count($migrations) == 0) {
            $this->note('<info>Nothing to migrate.</info>');
            return;
        }
        $batch = $this->repository->getNextBatchNumber();
        $pretend = Arr::get($options, 'pretend', false);
        $step = Arr::get($options, 'step', false);
        foreach ($migrations as $file) {
            $this->runUp($file, $batch, $pretend);
            if ($step) {
                $batch++;
            }
        }
    }
    protected function runUp($file, $batch, $pretend)
    {
        $file = $this->getMigrationName($file);
        $migration = $this->resolve($file);
        if ($pretend) {
            return $this->pretendToRun($migration, 'up');
        }
        $migration->up();
        $this->repository->log($file, $batch);
        $this->note("<info>Migrated:</info> {$file}");
    }
    public function rollback($paths = [], array $options = [])
    {
        $this->notes = [];
        $rolledBack = [];
        if (($steps = Arr::get($options, 'step', 0)) > 0) {
            $migrations = $this->repository->getMigrations($steps);
        } else {
            $migrations = $this->repository->getLast();
        }
        $count = count($migrations);
        $files = $this->getMigrationFiles($paths);
        if ($count === 0) {
            $this->note('<info>Nothing to rollback.</info>');
        } else {
            $this->requireFiles($files);
            foreach ($migrations as $migration) {
                $migration = (object) $migration;
                $rolledBack[] = $files[$migration->migration];
                $this->runDown($files[$migration->migration], $migration, Arr::get($options, 'pretend', false));
            }
        }
        return $rolledBack;
    }
    public function reset($paths = [], $pretend = false)
    {
        $this->notes = [];
        $rolledBack = [];
        $files = $this->getMigrationFiles($paths);
        $migrations = array_reverse($this->repository->getRan());
        $count = count($migrations);
        if ($count === 0) {
            $this->note('<info>Nothing to rollback.</info>');
        } else {
            $this->requireFiles($files);
            foreach ($migrations as $migration) {
                $rolledBack[] = $files[$migration];
                $this->runDown($files[$migration], (object) ['migration' => $migration], $pretend);
            }
        }
        return $rolledBack;
    }
    protected function runDown($file, $migration, $pretend)
    {
        $file = $this->getMigrationName($file);
        $instance = $this->resolve($file);
        if ($pretend) {
            return $this->pretendToRun($instance, 'down');
        }
        $instance->down();
        $this->repository->delete($migration);
        $this->note("<info>Rolled back:</info> {$file}");
    }
    public function getMigrationFiles($paths)
    {
        return Collection::make($paths)->flatMap(function ($path) {
            return $this->files->glob($path . '/*_*.php');
        })->filter()->sortBy(function ($file) {
            return $this->getMigrationName($file);
        })->values()->keyBy(function ($file) {
            return $this->getMigrationName($file);
        })->all();
    }
    public function requireFiles(array $files)
    {
        foreach ($files as $file) {
            $this->files->requireOnce($file);
        }
    }
    protected function pretendToRun($migration, $method)
    {
        foreach ($this->getQueries($migration, $method) as $query) {
            $name = get_class($migration);
            $this->note("<info>{$name}:</info> {$query['query']}");
        }
    }
    protected function getQueries($migration, $method)
    {
        $connection = $migration->getConnection();
        $db = $this->resolveConnection($connection);
        return $db->pretend(function () use($migration, $method) {
            $migration->{$method}();
        });
    }
    public function resolve($file)
    {
        $class = Str::studly(implode('_', array_slice(explode('_', $file), 4)));
        return new $class();
    }
    public function getMigrationName($path)
    {
        return str_replace('.php', '', basename($path));
    }
    protected function note($message)
    {
        $this->notes[] = $message;
    }
    public function getNotes()
    {
        return $this->notes;
    }
    public function resolveConnection($connection)
    {
        return $this->resolver->connection($connection);
    }
    public function path($path)
    {
        $this->paths[] = $path;
        $this->paths = array_unique($this->paths);
    }
    public function paths()
    {
        return $this->paths;
    }
    public function setConnection($name)
    {
        if (!is_null($name)) {
            $this->resolver->setDefaultConnection($name);
        }
        $this->repository->setSource($name);
        $this->connection = $name;
    }
    public function getRepository()
    {
        return $this->repository;
    }
    public function repositoryExists()
    {
        return $this->repository->repositoryExists();
    }
    public function getFilesystem()
    {
        return $this->files;
    }
}
}

namespace Illuminate\Database\Migrations {
abstract class Migration
{
    protected $connection;
    public function getConnection()
    {
        return $this->connection;
    }
}
}

namespace Illuminate\Database\Migrations {
interface MigrationRepositoryInterface
{
    public function getRan();
    public function getMigrations($steps);
    public function getLast();
    public function log($file, $batch);
    public function delete($migration);
    public function getNextBatchNumber();
    public function createRepository();
    public function repositoryExists();
    public function setSource($name);
}
}

namespace Illuminate\Database\Migrations {
use Illuminate\Database\ConnectionResolverInterface as Resolver;
class DatabaseMigrationRepository implements MigrationRepositoryInterface
{
    protected $resolver;
    protected $table;
    protected $connection;
    public function __construct(Resolver $resolver, $table)
    {
        $this->table = $table;
        $this->resolver = $resolver;
    }
    public function getRan()
    {
        return $this->table()->orderBy('batch', 'asc')->orderBy('migration', 'asc')->pluck('migration')->all();
    }
    public function getMigrations($steps)
    {
        $query = $this->table()->where('batch', '>=', '1');
        return $query->orderBy('migration', 'desc')->take($steps)->get()->all();
    }
    public function getLast()
    {
        $query = $this->table()->where('batch', $this->getLastBatchNumber());
        return $query->orderBy('migration', 'desc')->get()->all();
    }
    public function log($file, $batch)
    {
        $record = ['migration' => $file, 'batch' => $batch];
        $this->table()->insert($record);
    }
    public function delete($migration)
    {
        $this->table()->where('migration', $migration->migration)->delete();
    }
    public function getNextBatchNumber()
    {
        return $this->getLastBatchNumber() + 1;
    }
    public function getLastBatchNumber()
    {
        return $this->table()->max('batch');
    }
    public function createRepository()
    {
        $schema = $this->getConnection()->getSchemaBuilder();
        $schema->create($this->table, function ($table) {
            $table->string('migration');
            $table->integer('batch');
        });
    }
    public function repositoryExists()
    {
        $schema = $this->getConnection()->getSchemaBuilder();
        return $schema->hasTable($this->table);
    }
    protected function table()
    {
        return $this->getConnection()->table($this->table);
    }
    public function getConnectionResolver()
    {
        return $this->resolver;
    }
    public function getConnection()
    {
        return $this->resolver->connection($this->connection);
    }
    public function setSource($name)
    {
        $this->connection = $name;
    }
}
}

namespace Illuminate\Database\Schema {
use Closure;
use Illuminate\Support\Fluent;
use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Grammars\Grammar;
class Blueprint
{
    protected $table;
    protected $columns = [];
    protected $commands = [];
    public $engine;
    public $charset;
    public $collation;
    public $temporary = false;
    public function __construct($table, Closure $callback = null)
    {
        $this->table = $table;
        if (!is_null($callback)) {
            $callback($this);
        }
    }
    public function build(Connection $connection, Grammar $grammar)
    {
        foreach ($this->toSql($connection, $grammar) as $statement) {
            $connection->statement($statement);
        }
    }
    public function toSql(Connection $connection, Grammar $grammar)
    {
        $this->addImpliedCommands();
        $statements = [];
        foreach ($this->commands as $command) {
            $method = 'compile' . ucfirst($command->name);
            if (method_exists($grammar, $method)) {
                if (!is_null($sql = $grammar->{$method}($this, $command, $connection))) {
                    $statements = array_merge($statements, (array) $sql);
                }
            }
        }
        return $statements;
    }
    protected function addImpliedCommands()
    {
        if (count($this->getAddedColumns()) > 0 && !$this->creating()) {
            array_unshift($this->commands, $this->createCommand('add'));
        }
        if (count($this->getChangedColumns()) > 0 && !$this->creating()) {
            array_unshift($this->commands, $this->createCommand('change'));
        }
        $this->addFluentIndexes();
    }
    protected function addFluentIndexes()
    {
        foreach ($this->columns as $column) {
            foreach (['primary', 'unique', 'index'] as $index) {
                if ($column->{$index} === true) {
                    $this->{$index}($column->name);
                    continue 2;
                } elseif (isset($column->{$index})) {
                    $this->{$index}($column->name, $column->{$index});
                    continue 2;
                }
            }
        }
    }
    protected function creating()
    {
        foreach ($this->commands as $command) {
            if ($command->name == 'create') {
                return true;
            }
        }
        return false;
    }
    public function create()
    {
        return $this->addCommand('create');
    }
    public function temporary()
    {
        $this->temporary = true;
    }
    public function drop()
    {
        return $this->addCommand('drop');
    }
    public function dropIfExists()
    {
        return $this->addCommand('dropIfExists');
    }
    public function dropColumn($columns)
    {
        $columns = is_array($columns) ? $columns : (array) func_get_args();
        return $this->addCommand('dropColumn', compact('columns'));
    }
    public function renameColumn($from, $to)
    {
        return $this->addCommand('renameColumn', compact('from', 'to'));
    }
    public function dropPrimary($index = null)
    {
        return $this->dropIndexCommand('dropPrimary', 'primary', $index);
    }
    public function dropUnique($index)
    {
        return $this->dropIndexCommand('dropUnique', 'unique', $index);
    }
    public function dropIndex($index)
    {
        return $this->dropIndexCommand('dropIndex', 'index', $index);
    }
    public function dropForeign($index)
    {
        return $this->dropIndexCommand('dropForeign', 'foreign', $index);
    }
    public function dropTimestamps()
    {
        $this->dropColumn('created_at', 'updated_at');
    }
    public function dropTimestampsTz()
    {
        $this->dropTimestamps();
    }
    public function dropSoftDeletes()
    {
        $this->dropColumn('deleted_at');
    }
    public function dropSoftDeletesTz()
    {
        $this->dropSoftDeletes();
    }
    public function dropRememberToken()
    {
        $this->dropColumn('remember_token');
    }
    public function rename($to)
    {
        return $this->addCommand('rename', compact('to'));
    }
    public function primary($columns, $name = null, $algorithm = null)
    {
        return $this->indexCommand('primary', $columns, $name, $algorithm);
    }
    public function unique($columns, $name = null, $algorithm = null)
    {
        return $this->indexCommand('unique', $columns, $name, $algorithm);
    }
    public function index($columns, $name = null, $algorithm = null)
    {
        return $this->indexCommand('index', $columns, $name, $algorithm);
    }
    public function foreign($columns, $name = null)
    {
        return $this->indexCommand('foreign', $columns, $name);
    }
    public function increments($column)
    {
        return $this->unsignedInteger($column, true);
    }
    public function smallIncrements($column)
    {
        return $this->unsignedSmallInteger($column, true);
    }
    public function mediumIncrements($column)
    {
        return $this->unsignedMediumInteger($column, true);
    }
    public function bigIncrements($column)
    {
        return $this->unsignedBigInteger($column, true);
    }
    public function char($column, $length = 255)
    {
        return $this->addColumn('char', $column, compact('length'));
    }
    public function string($column, $length = 255)
    {
        return $this->addColumn('string', $column, compact('length'));
    }
    public function text($column)
    {
        return $this->addColumn('text', $column);
    }
    public function mediumText($column)
    {
        return $this->addColumn('mediumText', $column);
    }
    public function longText($column)
    {
        return $this->addColumn('longText', $column);
    }
    public function integer($column, $autoIncrement = false, $unsigned = false)
    {
        return $this->addColumn('integer', $column, compact('autoIncrement', 'unsigned'));
    }
    public function tinyInteger($column, $autoIncrement = false, $unsigned = false)
    {
        return $this->addColumn('tinyInteger', $column, compact('autoIncrement', 'unsigned'));
    }
    public function smallInteger($column, $autoIncrement = false, $unsigned = false)
    {
        return $this->addColumn('smallInteger', $column, compact('autoIncrement', 'unsigned'));
    }
    public function mediumInteger($column, $autoIncrement = false, $unsigned = false)
    {
        return $this->addColumn('mediumInteger', $column, compact('autoIncrement', 'unsigned'));
    }
    public function bigInteger($column, $autoIncrement = false, $unsigned = false)
    {
        return $this->addColumn('bigInteger', $column, compact('autoIncrement', 'unsigned'));
    }
    public function unsignedTinyInteger($column, $autoIncrement = false)
    {
        return $this->tinyInteger($column, $autoIncrement, true);
    }
    public function unsignedSmallInteger($column, $autoIncrement = false)
    {
        return $this->smallInteger($column, $autoIncrement, true);
    }
    public function unsignedMediumInteger($column, $autoIncrement = false)
    {
        return $this->mediumInteger($column, $autoIncrement, true);
    }
    public function unsignedInteger($column, $autoIncrement = false)
    {
        return $this->integer($column, $autoIncrement, true);
    }
    public function unsignedBigInteger($column, $autoIncrement = false)
    {
        return $this->bigInteger($column, $autoIncrement, true);
    }
    public function float($column, $total = 8, $places = 2)
    {
        return $this->addColumn('float', $column, compact('total', 'places'));
    }
    public function double($column, $total = null, $places = null)
    {
        return $this->addColumn('double', $column, compact('total', 'places'));
    }
    public function decimal($column, $total = 8, $places = 2)
    {
        return $this->addColumn('decimal', $column, compact('total', 'places'));
    }
    public function boolean($column)
    {
        return $this->addColumn('boolean', $column);
    }
    public function enum($column, array $allowed)
    {
        return $this->addColumn('enum', $column, compact('allowed'));
    }
    public function json($column)
    {
        return $this->addColumn('json', $column);
    }
    public function jsonb($column)
    {
        return $this->addColumn('jsonb', $column);
    }
    public function date($column)
    {
        return $this->addColumn('date', $column);
    }
    public function dateTime($column)
    {
        return $this->addColumn('dateTime', $column);
    }
    public function dateTimeTz($column)
    {
        return $this->addColumn('dateTimeTz', $column);
    }
    public function time($column)
    {
        return $this->addColumn('time', $column);
    }
    public function timeTz($column)
    {
        return $this->addColumn('timeTz', $column);
    }
    public function timestamp($column)
    {
        return $this->addColumn('timestamp', $column);
    }
    public function timestampTz($column)
    {
        return $this->addColumn('timestampTz', $column);
    }
    public function nullableTimestamps()
    {
        $this->timestamps();
    }
    public function timestamps()
    {
        $this->timestamp('created_at')->nullable();
        $this->timestamp('updated_at')->nullable();
    }
    public function timestampsTz()
    {
        $this->timestampTz('created_at')->nullable();
        $this->timestampTz('updated_at')->nullable();
    }
    public function softDeletes()
    {
        return $this->timestamp('deleted_at')->nullable();
    }
    public function softDeletesTz()
    {
        return $this->timestampTz('deleted_at')->nullable();
    }
    public function binary($column)
    {
        return $this->addColumn('binary', $column);
    }
    public function uuid($column)
    {
        return $this->addColumn('uuid', $column);
    }
    public function ipAddress($column)
    {
        return $this->addColumn('ipAddress', $column);
    }
    public function macAddress($column)
    {
        return $this->addColumn('macAddress', $column);
    }
    public function morphs($name, $indexName = null)
    {
        $this->unsignedInteger("{$name}_id");
        $this->string("{$name}_type");
        $this->index(["{$name}_id", "{$name}_type"], $indexName);
    }
    public function rememberToken()
    {
        return $this->string('remember_token', 100)->nullable();
    }
    protected function dropIndexCommand($command, $type, $index)
    {
        $columns = [];
        if (is_array($index)) {
            $columns = $index;
            $index = $this->createIndexName($type, $columns);
        }
        return $this->indexCommand($command, $columns, $index);
    }
    protected function indexCommand($type, $columns, $index, $algorithm = null)
    {
        $columns = (array) $columns;
        if (is_null($index)) {
            $index = $this->createIndexName($type, $columns);
        }
        return $this->addCommand($type, compact('index', 'columns', 'algorithm'));
    }
    protected function createIndexName($type, array $columns)
    {
        $index = strtolower($this->table . '_' . implode('_', $columns) . '_' . $type);
        return str_replace(['-', '.'], '_', $index);
    }
    public function addColumn($type, $name, array $parameters = [])
    {
        $attributes = array_merge(compact('type', 'name'), $parameters);
        $this->columns[] = $column = new Fluent($attributes);
        return $column;
    }
    public function removeColumn($name)
    {
        $this->columns = array_values(array_filter($this->columns, function ($c) use($name) {
            return $c['attributes']['name'] != $name;
        }));
        return $this;
    }
    protected function addCommand($name, array $parameters = [])
    {
        $this->commands[] = $command = $this->createCommand($name, $parameters);
        return $command;
    }
    protected function createCommand($name, array $parameters = [])
    {
        return new Fluent(array_merge(compact('name'), $parameters));
    }
    public function getTable()
    {
        return $this->table;
    }
    public function getColumns()
    {
        return $this->columns;
    }
    public function getCommands()
    {
        return $this->commands;
    }
    public function getAddedColumns()
    {
        return array_filter($this->columns, function ($column) {
            return !$column->change;
        });
    }
    public function getChangedColumns()
    {
        return array_filter($this->columns, function ($column) {
            return (bool) $column->change;
        });
    }
}
}

namespace Illuminate\Database\Schema\Grammars {
use RuntimeException;
use Doctrine\DBAL\Types\Type;
use Illuminate\Support\Fluent;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Schema\Column;
use Doctrine\DBAL\Schema\TableDiff;
use Illuminate\Database\Connection;
use Doctrine\DBAL\Schema\Comparator;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Grammar as BaseGrammar;
use Doctrine\DBAL\Schema\AbstractSchemaManager as SchemaManager;
abstract class Grammar extends BaseGrammar
{
    public function compileRenameColumn(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        $schema = $connection->getDoctrineSchemaManager();
        $table = $this->getTablePrefix() . $blueprint->getTable();
        $column = $connection->getDoctrineColumn($table, $command->from);
        $tableDiff = $this->getRenamedDiff($blueprint, $command, $column, $schema);
        return (array) $schema->getDatabasePlatform()->getAlterTableSQL($tableDiff);
    }
    protected function getRenamedDiff(Blueprint $blueprint, Fluent $command, Column $column, SchemaManager $schema)
    {
        $tableDiff = $this->getDoctrineTableDiff($blueprint, $schema);
        return $this->setRenamedColumns($tableDiff, $command, $column);
    }
    protected function setRenamedColumns(TableDiff $tableDiff, Fluent $command, Column $column)
    {
        $newColumn = new Column($command->to, $column->getType(), $column->toArray());
        $tableDiff->renamedColumns = [$command->from => $newColumn];
        return $tableDiff;
    }
    public function compileForeign(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        $on = $this->wrapTable($command->on);
        $columns = $this->columnize($command->columns);
        $onColumns = $this->columnize((array) $command->references);
        $sql = "alter table {$table} add constraint {$index} ";
        $sql .= "foreign key ({$columns}) references {$on} ({$onColumns})";
        if (!is_null($command->onDelete)) {
            $sql .= " on delete {$command->onDelete}";
        }
        if (!is_null($command->onUpdate)) {
            $sql .= " on update {$command->onUpdate}";
        }
        return $sql;
    }
    protected function getColumns(Blueprint $blueprint)
    {
        $columns = [];
        foreach ($blueprint->getAddedColumns() as $column) {
            $sql = $this->wrap($column) . ' ' . $this->getType($column);
            $columns[] = $this->addModifiers($sql, $blueprint, $column);
        }
        return $columns;
    }
    protected function addModifiers($sql, Blueprint $blueprint, Fluent $column)
    {
        foreach ($this->modifiers as $modifier) {
            if (method_exists($this, $method = "modify{$modifier}")) {
                $sql .= $this->{$method}($blueprint, $column);
            }
        }
        return $sql;
    }
    protected function getCommandByName(Blueprint $blueprint, $name)
    {
        $commands = $this->getCommandsByName($blueprint, $name);
        if (count($commands) > 0) {
            return reset($commands);
        }
    }
    protected function getCommandsByName(Blueprint $blueprint, $name)
    {
        return array_filter($blueprint->getCommands(), function ($value) use($name) {
            return $value->name == $name;
        });
    }
    protected function getType(Fluent $column)
    {
        return $this->{'type' . ucfirst($column->type)}($column);
    }
    public function prefixArray($prefix, array $values)
    {
        return array_map(function ($value) use($prefix) {
            return $prefix . ' ' . $value;
        }, $values);
    }
    public function wrapTable($table)
    {
        if ($table instanceof Blueprint) {
            $table = $table->getTable();
        }
        return parent::wrapTable($table);
    }
    public function wrap($value, $prefixAlias = false)
    {
        if ($value instanceof Fluent) {
            $value = $value->name;
        }
        return parent::wrap($value, $prefixAlias);
    }
    protected function getDefaultValue($value)
    {
        if ($value instanceof Expression) {
            return $value;
        }
        if (is_bool($value)) {
            return "'" . (int) $value . "'";
        }
        return "'" . strval($value) . "'";
    }
    protected function getDoctrineTableDiff(Blueprint $blueprint, SchemaManager $schema)
    {
        $table = $this->getTablePrefix() . $blueprint->getTable();
        $tableDiff = new TableDiff($table);
        $tableDiff->fromTable = $schema->listTableDetails($table);
        return $tableDiff;
    }
    public function compileChange(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        if (!$connection->isDoctrineAvailable()) {
            throw new RuntimeException(sprintf('Changing columns for table "%s" requires Doctrine DBAL; install "doctrine/dbal".', $blueprint->getTable()));
        }
        $schema = $connection->getDoctrineSchemaManager();
        $tableDiff = $this->getChangedDiff($blueprint, $schema);
        if ($tableDiff !== false) {
            return (array) $schema->getDatabasePlatform()->getAlterTableSQL($tableDiff);
        }
        return [];
    }
    protected function getChangedDiff(Blueprint $blueprint, SchemaManager $schema)
    {
        $table = $schema->listTableDetails($this->getTablePrefix() . $blueprint->getTable());
        return (new Comparator())->diffTable($table, $this->getTableWithColumnChanges($blueprint, $table));
    }
    protected function getTableWithColumnChanges(Blueprint $blueprint, Table $table)
    {
        $table = clone $table;
        foreach ($blueprint->getChangedColumns() as $fluent) {
            $column = $this->getDoctrineColumnForChange($table, $fluent);
            foreach ($fluent->getAttributes() as $key => $value) {
                if (!is_null($option = $this->mapFluentOptionToDoctrine($key))) {
                    if (method_exists($column, $method = 'set' . ucfirst($option))) {
                        $column->{$method}($this->mapFluentValueToDoctrine($option, $value));
                    }
                }
            }
        }
        return $table;
    }
    protected function getDoctrineColumnForChange(Table $table, Fluent $fluent)
    {
        return $table->changeColumn($fluent['name'], $this->getDoctrineColumnChangeOptions($fluent))->getColumn($fluent['name']);
    }
    protected function getDoctrineColumnChangeOptions(Fluent $fluent)
    {
        $options = ['type' => $this->getDoctrineColumnType($fluent['type'])];
        if (in_array($fluent['type'], ['text', 'mediumText', 'longText'])) {
            $options['length'] = $this->calculateDoctrineTextLength($fluent['type']);
        }
        return $options;
    }
    protected function getDoctrineColumnType($type)
    {
        $type = strtolower($type);
        switch ($type) {
            case 'biginteger':
                $type = 'bigint';
                break;
            case 'smallinteger':
                $type = 'smallint';
                break;
            case 'mediumtext':
            case 'longtext':
                $type = 'text';
                break;
            case 'binary':
                $type = 'blob';
                break;
        }
        return Type::getType($type);
    }
    protected function calculateDoctrineTextLength($type)
    {
        switch ($type) {
            case 'mediumText':
                return 65535 + 1;
            case 'longText':
                return 16777215 + 1;
            default:
                return 255 + 1;
        }
    }
    protected function mapFluentOptionToDoctrine($attribute)
    {
        switch ($attribute) {
            case 'type':
            case 'name':
                return;
            case 'nullable':
                return 'notnull';
            case 'total':
                return 'precision';
            case 'places':
                return 'scale';
            default:
                return $attribute;
        }
    }
    protected function mapFluentValueToDoctrine($option, $value)
    {
        return $option == 'notnull' ? !$value : $value;
    }
}
}

namespace Illuminate\Database\Schema\Grammars {
use Illuminate\Support\Fluent;
use Illuminate\Database\Schema\Blueprint;
class SqlServerGrammar extends Grammar
{
    protected $modifiers = ['Increment', 'Nullable', 'Default'];
    protected $serials = ['tinyInteger', 'smallInteger', 'mediumInteger', 'integer', 'bigInteger'];
    public function compileTableExists()
    {
        return "select * from sysobjects where type = 'U' and name = ?";
    }
    public function compileColumnExists($table)
    {
        return "select col.name from sys.columns as col\n                join sys.objects as obj on col.object_id = obj.object_id\n                where obj.type = 'U' and obj.name = '{$table}'";
    }
    public function compileCreate(Blueprint $blueprint, Fluent $command)
    {
        $columns = implode(', ', $this->getColumns($blueprint));
        return 'create table ' . $this->wrapTable($blueprint) . " ({$columns})";
    }
    public function compileAdd(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $columns = $this->getColumns($blueprint);
        return 'alter table ' . $table . ' add ' . implode(', ', $columns);
    }
    public function compilePrimary(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->columnize($command->columns);
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "alter table {$table} add constraint {$index} primary key ({$columns})";
    }
    public function compileUnique(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->columnize($command->columns);
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "create unique index {$index} on {$table} ({$columns})";
    }
    public function compileIndex(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->columnize($command->columns);
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "create index {$index} on {$table} ({$columns})";
    }
    public function compileDrop(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table ' . $this->wrapTable($blueprint);
    }
    public function compileDropIfExists(Blueprint $blueprint, Fluent $command)
    {
        return 'if exists (select * from INFORMATION_SCHEMA.TABLES where TABLE_NAME = \'' . $blueprint->getTable() . '\') drop table [' . $blueprint->getTable() . ']';
    }
    public function compileDropColumn(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->wrapArray($command->columns);
        $table = $this->wrapTable($blueprint);
        return 'alter table ' . $table . ' drop column ' . implode(', ', $columns);
    }
    public function compileDropPrimary(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "alter table {$table} drop constraint {$index}";
    }
    public function compileDropUnique(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "drop index {$index} on {$table}";
    }
    public function compileDropIndex(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "drop index {$index} on {$table}";
    }
    public function compileDropForeign(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "alter table {$table} drop constraint {$index}";
    }
    public function compileRename(Blueprint $blueprint, Fluent $command)
    {
        $from = $this->wrapTable($blueprint);
        return "sp_rename {$from}, " . $this->wrapTable($command->to);
    }
    public function compileEnableForeignKeyConstraints()
    {
        return 'EXEC sp_msforeachtable @command1="print \'?\'", @command2="ALTER TABLE ? WITH CHECK CHECK CONSTRAINT all";';
    }
    public function compileDisableForeignKeyConstraints()
    {
        return 'EXEC sp_msforeachtable "ALTER TABLE ? NOCHECK CONSTRAINT all";';
    }
    protected function typeChar(Fluent $column)
    {
        return "nchar({$column->length})";
    }
    protected function typeString(Fluent $column)
    {
        return "nvarchar({$column->length})";
    }
    protected function typeText(Fluent $column)
    {
        return 'nvarchar(max)';
    }
    protected function typeMediumText(Fluent $column)
    {
        return 'nvarchar(max)';
    }
    protected function typeLongText(Fluent $column)
    {
        return 'nvarchar(max)';
    }
    protected function typeInteger(Fluent $column)
    {
        return 'int';
    }
    protected function typeBigInteger(Fluent $column)
    {
        return 'bigint';
    }
    protected function typeMediumInteger(Fluent $column)
    {
        return 'int';
    }
    protected function typeTinyInteger(Fluent $column)
    {
        return 'tinyint';
    }
    protected function typeSmallInteger(Fluent $column)
    {
        return 'smallint';
    }
    protected function typeFloat(Fluent $column)
    {
        return 'float';
    }
    protected function typeDouble(Fluent $column)
    {
        return 'float';
    }
    protected function typeDecimal(Fluent $column)
    {
        return "decimal({$column->total}, {$column->places})";
    }
    protected function typeBoolean(Fluent $column)
    {
        return 'bit';
    }
    protected function typeEnum(Fluent $column)
    {
        return 'nvarchar(255)';
    }
    protected function typeJson(Fluent $column)
    {
        return 'nvarchar(max)';
    }
    protected function typeJsonb(Fluent $column)
    {
        return 'nvarchar(max)';
    }
    protected function typeDate(Fluent $column)
    {
        return 'date';
    }
    protected function typeDateTime(Fluent $column)
    {
        return 'datetime';
    }
    protected function typeDateTimeTz(Fluent $column)
    {
        return 'datetimeoffset(0)';
    }
    protected function typeTime(Fluent $column)
    {
        return 'time';
    }
    protected function typeTimeTz(Fluent $column)
    {
        return 'time';
    }
    protected function typeTimestamp(Fluent $column)
    {
        if ($column->useCurrent) {
            return 'datetime default CURRENT_TIMESTAMP';
        }
        return 'datetime';
    }
    protected function typeTimestampTz(Fluent $column)
    {
        if ($column->useCurrent) {
            return 'datetimeoffset(0) default CURRENT_TIMESTAMP';
        }
        return 'datetimeoffset(0)';
    }
    protected function typeBinary(Fluent $column)
    {
        return 'varbinary(max)';
    }
    protected function typeUuid(Fluent $column)
    {
        return 'uniqueidentifier';
    }
    protected function typeIpAddress(Fluent $column)
    {
        return 'nvarchar(45)';
    }
    protected function typeMacAddress(Fluent $column)
    {
        return 'nvarchar(17)';
    }
    protected function modifyNullable(Blueprint $blueprint, Fluent $column)
    {
        return $column->nullable ? ' null' : ' not null';
    }
    protected function modifyDefault(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->default)) {
            return ' default ' . $this->getDefaultValue($column->default);
        }
    }
    protected function modifyIncrement(Blueprint $blueprint, Fluent $column)
    {
        if (in_array($column->type, $this->serials) && $column->autoIncrement) {
            return ' identity primary key';
        }
    }
}
}

namespace Illuminate\Database\Schema\Grammars {
use Illuminate\Support\Fluent;
use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Blueprint;
class MySqlGrammar extends Grammar
{
    protected $modifiers = ['VirtualAs', 'StoredAs', 'Unsigned', 'Charset', 'Collate', 'Nullable', 'Default', 'Increment', 'Comment', 'After', 'First'];
    protected $serials = ['bigInteger', 'integer', 'mediumInteger', 'smallInteger', 'tinyInteger'];
    public function compileTableExists()
    {
        return 'select * from information_schema.tables where table_schema = ? and table_name = ?';
    }
    public function compileColumnExists()
    {
        return 'select column_name from information_schema.columns where table_schema = ? and table_name = ?';
    }
    public function compileCreate(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        $columns = implode(', ', $this->getColumns($blueprint));
        $sql = $blueprint->temporary ? 'create temporary' : 'create';
        $sql .= ' table ' . $this->wrapTable($blueprint) . " ({$columns})";
        $sql = $this->compileCreateEncoding($sql, $connection, $blueprint);
        if (isset($blueprint->engine)) {
            $sql .= ' engine = ' . $blueprint->engine;
        } elseif (!is_null($engine = $connection->getConfig('engine'))) {
            $sql .= ' engine = ' . $engine;
        }
        return $sql;
    }
    protected function compileCreateEncoding($sql, Connection $connection, Blueprint $blueprint)
    {
        if (isset($blueprint->charset)) {
            $sql .= ' default character set ' . $blueprint->charset;
        } elseif (!is_null($charset = $connection->getConfig('charset'))) {
            $sql .= ' default character set ' . $charset;
        }
        if (isset($blueprint->collation)) {
            $sql .= ' collate ' . $blueprint->collation;
        } elseif (!is_null($collation = $connection->getConfig('collation'))) {
            $sql .= ' collate ' . $collation;
        }
        return $sql;
    }
    public function compileAdd(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $columns = $this->prefixArray('add', $this->getColumns($blueprint));
        return 'alter table ' . $table . ' ' . implode(', ', $columns);
    }
    public function compilePrimary(Blueprint $blueprint, Fluent $command)
    {
        $command->name(null);
        return $this->compileKey($blueprint, $command, 'primary key');
    }
    public function compileUnique(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileKey($blueprint, $command, 'unique');
    }
    public function compileIndex(Blueprint $blueprint, Fluent $command)
    {
        return $this->compileKey($blueprint, $command, 'index');
    }
    protected function compileKey(Blueprint $blueprint, Fluent $command, $type)
    {
        $columns = $this->columnize($command->columns);
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        $algorithm = $command->algorithm ? ' using ' . $command->algorithm : '';
        return "alter table {$table} add {$type} {$index}{$algorithm}({$columns})";
    }
    public function compileDrop(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table ' . $this->wrapTable($blueprint);
    }
    public function compileDropIfExists(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table if exists ' . $this->wrapTable($blueprint);
    }
    public function compileDropColumn(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->prefixArray('drop', $this->wrapArray($command->columns));
        $table = $this->wrapTable($blueprint);
        return 'alter table ' . $table . ' ' . implode(', ', $columns);
    }
    public function compileDropPrimary(Blueprint $blueprint, Fluent $command)
    {
        return 'alter table ' . $this->wrapTable($blueprint) . ' drop primary key';
    }
    public function compileDropUnique(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "alter table {$table} drop index {$index}";
    }
    public function compileDropIndex(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "alter table {$table} drop index {$index}";
    }
    public function compileDropForeign(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "alter table {$table} drop foreign key {$index}";
    }
    public function compileRename(Blueprint $blueprint, Fluent $command)
    {
        $from = $this->wrapTable($blueprint);
        return "rename table {$from} to " . $this->wrapTable($command->to);
    }
    public function compileEnableForeignKeyConstraints()
    {
        return 'SET FOREIGN_KEY_CHECKS=1;';
    }
    public function compileDisableForeignKeyConstraints()
    {
        return 'SET FOREIGN_KEY_CHECKS=0;';
    }
    protected function typeChar(Fluent $column)
    {
        return "char({$column->length})";
    }
    protected function typeString(Fluent $column)
    {
        return "varchar({$column->length})";
    }
    protected function typeText(Fluent $column)
    {
        return 'text';
    }
    protected function typeMediumText(Fluent $column)
    {
        return 'mediumtext';
    }
    protected function typeLongText(Fluent $column)
    {
        return 'longtext';
    }
    protected function typeBigInteger(Fluent $column)
    {
        return 'bigint';
    }
    protected function typeInteger(Fluent $column)
    {
        return 'int';
    }
    protected function typeMediumInteger(Fluent $column)
    {
        return 'mediumint';
    }
    protected function typeTinyInteger(Fluent $column)
    {
        return 'tinyint';
    }
    protected function typeSmallInteger(Fluent $column)
    {
        return 'smallint';
    }
    protected function typeFloat(Fluent $column)
    {
        return $this->typeDouble($column);
    }
    protected function typeDouble(Fluent $column)
    {
        if ($column->total && $column->places) {
            return "double({$column->total}, {$column->places})";
        }
        return 'double';
    }
    protected function typeDecimal(Fluent $column)
    {
        return "decimal({$column->total}, {$column->places})";
    }
    protected function typeBoolean(Fluent $column)
    {
        return 'tinyint(1)';
    }
    protected function typeEnum(Fluent $column)
    {
        return "enum('" . implode("', '", $column->allowed) . "')";
    }
    protected function typeJson(Fluent $column)
    {
        return 'json';
    }
    protected function typeJsonb(Fluent $column)
    {
        return 'json';
    }
    protected function typeDate(Fluent $column)
    {
        return 'date';
    }
    protected function typeDateTime(Fluent $column)
    {
        return 'datetime';
    }
    protected function typeDateTimeTz(Fluent $column)
    {
        return 'datetime';
    }
    protected function typeTime(Fluent $column)
    {
        return 'time';
    }
    protected function typeTimeTz(Fluent $column)
    {
        return 'time';
    }
    protected function typeTimestamp(Fluent $column)
    {
        if ($column->useCurrent) {
            return 'timestamp default CURRENT_TIMESTAMP';
        }
        return 'timestamp';
    }
    protected function typeTimestampTz(Fluent $column)
    {
        if ($column->useCurrent) {
            return 'timestamp default CURRENT_TIMESTAMP';
        }
        return 'timestamp';
    }
    protected function typeBinary(Fluent $column)
    {
        return 'blob';
    }
    protected function typeUuid(Fluent $column)
    {
        return 'char(36)';
    }
    protected function typeIpAddress(Fluent $column)
    {
        return 'varchar(45)';
    }
    protected function typeMacAddress(Fluent $column)
    {
        return 'varchar(17)';
    }
    protected function modifyVirtualAs(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->virtualAs)) {
            return " as ({$column->virtualAs})";
        }
    }
    protected function modifyStoredAs(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->storedAs)) {
            return " as ({$column->storedAs}) stored";
        }
    }
    protected function modifyUnsigned(Blueprint $blueprint, Fluent $column)
    {
        if ($column->unsigned) {
            return ' unsigned';
        }
    }
    protected function modifyCharset(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->charset)) {
            return ' character set ' . $column->charset;
        }
    }
    protected function modifyCollate(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->collation)) {
            return ' collate ' . $column->collation;
        }
    }
    protected function modifyNullable(Blueprint $blueprint, Fluent $column)
    {
        return $column->nullable ? ' null' : ' not null';
    }
    protected function modifyDefault(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->default)) {
            return ' default ' . $this->getDefaultValue($column->default);
        }
    }
    protected function modifyIncrement(Blueprint $blueprint, Fluent $column)
    {
        if (in_array($column->type, $this->serials) && $column->autoIncrement) {
            return ' auto_increment primary key';
        }
    }
    protected function modifyFirst(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->first)) {
            return ' first';
        }
    }
    protected function modifyAfter(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->after)) {
            return ' after ' . $this->wrap($column->after);
        }
    }
    protected function modifyComment(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->comment)) {
            return " comment '" . $column->comment . "'";
        }
    }
    protected function wrapValue($value)
    {
        if ($value === '*') {
            return $value;
        }
        return '`' . str_replace('`', '``', $value) . '`';
    }
}
}

namespace Illuminate\Database\Schema\Grammars {
use Illuminate\Support\Fluent;
use Illuminate\Database\Schema\Blueprint;
class PostgresGrammar extends Grammar
{
    protected $modifiers = ['Increment', 'Nullable', 'Default'];
    protected $serials = ['bigInteger', 'integer', 'mediumInteger', 'smallInteger', 'tinyInteger'];
    public function compileTableExists()
    {
        return 'select * from information_schema.tables where table_schema = ? and table_name = ?';
    }
    public function compileColumnExists($table)
    {
        return "select column_name from information_schema.columns where table_name = '{$table}'";
    }
    public function compileCreate(Blueprint $blueprint, Fluent $command)
    {
        $columns = implode(', ', $this->getColumns($blueprint));
        $sql = $blueprint->temporary ? 'create temporary' : 'create';
        $sql .= ' table ' . $this->wrapTable($blueprint) . " ({$columns})";
        return $sql;
    }
    public function compileAdd(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $columns = $this->prefixArray('add column', $this->getColumns($blueprint));
        return 'alter table ' . $table . ' ' . implode(', ', $columns);
    }
    public function compilePrimary(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->columnize($command->columns);
        return 'alter table ' . $this->wrapTable($blueprint) . " add primary key ({$columns})";
    }
    public function compileUnique(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        $columns = $this->columnize($command->columns);
        return "alter table {$table} add constraint {$index} unique ({$columns})";
    }
    public function compileIndex(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->columnize($command->columns);
        $index = $this->wrap($command->index);
        $algorithm = $command->algorithm ? ' using ' . $command->algorithm : '';
        return "create index {$index} on " . $this->wrapTable($blueprint) . $algorithm . " ({$columns})";
    }
    public function compileDrop(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table ' . $this->wrapTable($blueprint);
    }
    public function compileDropIfExists(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table if exists ' . $this->wrapTable($blueprint);
    }
    public function compileDropColumn(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->prefixArray('drop column', $this->wrapArray($command->columns));
        $table = $this->wrapTable($blueprint);
        return 'alter table ' . $table . ' ' . implode(', ', $columns);
    }
    public function compileDropPrimary(Blueprint $blueprint, Fluent $command)
    {
        $table = $blueprint->getTable();
        $index = $this->wrap("{$table}_pkey");
        return 'alter table ' . $this->wrapTable($blueprint) . " drop constraint {$index}";
    }
    public function compileDropUnique(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "alter table {$table} drop constraint {$index}";
    }
    public function compileDropIndex(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "drop index {$index}";
    }
    public function compileDropForeign(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "alter table {$table} drop constraint {$index}";
    }
    public function compileEnableForeignKeyConstraints()
    {
        return 'SET CONSTRAINTS ALL IMMEDIATE;';
    }
    public function compileDisableForeignKeyConstraints()
    {
        return 'SET CONSTRAINTS ALL DEFERRED;';
    }
    public function compileRename(Blueprint $blueprint, Fluent $command)
    {
        $from = $this->wrapTable($blueprint);
        return "alter table {$from} rename to " . $this->wrapTable($command->to);
    }
    protected function typeChar(Fluent $column)
    {
        return "char({$column->length})";
    }
    protected function typeString(Fluent $column)
    {
        return "varchar({$column->length})";
    }
    protected function typeText(Fluent $column)
    {
        return 'text';
    }
    protected function typeMediumText(Fluent $column)
    {
        return 'text';
    }
    protected function typeLongText(Fluent $column)
    {
        return 'text';
    }
    protected function typeInteger(Fluent $column)
    {
        return $column->autoIncrement ? 'serial' : 'integer';
    }
    protected function typeBigInteger(Fluent $column)
    {
        return $column->autoIncrement ? 'bigserial' : 'bigint';
    }
    protected function typeMediumInteger(Fluent $column)
    {
        return $column->autoIncrement ? 'serial' : 'integer';
    }
    protected function typeTinyInteger(Fluent $column)
    {
        return $column->autoIncrement ? 'smallserial' : 'smallint';
    }
    protected function typeSmallInteger(Fluent $column)
    {
        return $column->autoIncrement ? 'smallserial' : 'smallint';
    }
    protected function typeFloat(Fluent $column)
    {
        return $this->typeDouble($column);
    }
    protected function typeDouble(Fluent $column)
    {
        return 'double precision';
    }
    protected function typeDecimal(Fluent $column)
    {
        return "decimal({$column->total}, {$column->places})";
    }
    protected function typeBoolean(Fluent $column)
    {
        return 'boolean';
    }
    protected function typeEnum(Fluent $column)
    {
        $allowed = array_map(function ($a) {
            return "'{$a}'";
        }, $column->allowed);
        return "varchar(255) check (\"{$column->name}\" in (" . implode(', ', $allowed) . '))';
    }
    protected function typeJson(Fluent $column)
    {
        return 'json';
    }
    protected function typeJsonb(Fluent $column)
    {
        return 'jsonb';
    }
    protected function typeDate(Fluent $column)
    {
        return 'date';
    }
    protected function typeDateTime(Fluent $column)
    {
        return 'timestamp(0) without time zone';
    }
    protected function typeDateTimeTz(Fluent $column)
    {
        return 'timestamp(0) with time zone';
    }
    protected function typeTime(Fluent $column)
    {
        return 'time(0) without time zone';
    }
    protected function typeTimeTz(Fluent $column)
    {
        return 'time(0) with time zone';
    }
    protected function typeTimestamp(Fluent $column)
    {
        if ($column->useCurrent) {
            return 'timestamp(0) without time zone default CURRENT_TIMESTAMP(0)';
        }
        return 'timestamp(0) without time zone';
    }
    protected function typeTimestampTz(Fluent $column)
    {
        if ($column->useCurrent) {
            return 'timestamp(0) with time zone default CURRENT_TIMESTAMP(0)';
        }
        return 'timestamp(0) with time zone';
    }
    protected function typeBinary(Fluent $column)
    {
        return 'bytea';
    }
    protected function typeUuid(Fluent $column)
    {
        return 'uuid';
    }
    protected function typeIpAddress(Fluent $column)
    {
        return 'inet';
    }
    protected function typeMacAddress(Fluent $column)
    {
        return 'macaddr';
    }
    protected function modifyNullable(Blueprint $blueprint, Fluent $column)
    {
        return $column->nullable ? ' null' : ' not null';
    }
    protected function modifyDefault(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->default)) {
            return ' default ' . $this->getDefaultValue($column->default);
        }
    }
    protected function modifyIncrement(Blueprint $blueprint, Fluent $column)
    {
        if (in_array($column->type, $this->serials) && $column->autoIncrement) {
            return ' primary key';
        }
    }
}
}

namespace Illuminate\Database\Schema\Grammars {
use Illuminate\Support\Fluent;
use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Blueprint;
class SQLiteGrammar extends Grammar
{
    protected $modifiers = ['Nullable', 'Default', 'Increment'];
    protected $serials = ['bigInteger', 'integer', 'mediumInteger', 'smallInteger', 'tinyInteger'];
    public function compileTableExists()
    {
        return "select * from sqlite_master where type = 'table' and name = ?";
    }
    public function compileColumnExists($table)
    {
        return 'pragma table_info(' . str_replace('.', '__', $table) . ')';
    }
    public function compileCreate(Blueprint $blueprint, Fluent $command)
    {
        $columns = implode(', ', $this->getColumns($blueprint));
        $sql = $blueprint->temporary ? 'create temporary' : 'create';
        $sql .= ' table ' . $this->wrapTable($blueprint) . " ({$columns}";
        $sql .= (string) $this->addForeignKeys($blueprint);
        $sql .= (string) $this->addPrimaryKeys($blueprint);
        return $sql . ')';
    }
    protected function addForeignKeys(Blueprint $blueprint)
    {
        $sql = '';
        $foreigns = $this->getCommandsByName($blueprint, 'foreign');
        foreach ($foreigns as $foreign) {
            $sql .= $this->getForeignKey($foreign);
            if (!is_null($foreign->onDelete)) {
                $sql .= " on delete {$foreign->onDelete}";
            }
            if (!is_null($foreign->onUpdate)) {
                $sql .= " on update {$foreign->onUpdate}";
            }
        }
        return $sql;
    }
    protected function getForeignKey($foreign)
    {
        $on = $this->wrapTable($foreign->on);
        $columns = $this->columnize($foreign->columns);
        $onColumns = $this->columnize((array) $foreign->references);
        return ", foreign key({$columns}) references {$on}({$onColumns})";
    }
    protected function addPrimaryKeys(Blueprint $blueprint)
    {
        $primary = $this->getCommandByName($blueprint, 'primary');
        if (!is_null($primary)) {
            $columns = $this->columnize($primary->columns);
            return ", primary key ({$columns})";
        }
    }
    public function compileAdd(Blueprint $blueprint, Fluent $command)
    {
        $table = $this->wrapTable($blueprint);
        $columns = $this->prefixArray('add column', $this->getColumns($blueprint));
        $statements = [];
        foreach ($columns as $column) {
            $statements[] = 'alter table ' . $table . ' ' . $column;
        }
        return $statements;
    }
    public function compileUnique(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->columnize($command->columns);
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "create unique index {$index} on {$table} ({$columns})";
    }
    public function compileIndex(Blueprint $blueprint, Fluent $command)
    {
        $columns = $this->columnize($command->columns);
        $table = $this->wrapTable($blueprint);
        $index = $this->wrap($command->index);
        return "create index {$index} on {$table} ({$columns})";
    }
    public function compileForeign(Blueprint $blueprint, Fluent $command)
    {
    }
    public function compileDrop(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table ' . $this->wrapTable($blueprint);
    }
    public function compileDropIfExists(Blueprint $blueprint, Fluent $command)
    {
        return 'drop table if exists ' . $this->wrapTable($blueprint);
    }
    public function compileDropColumn(Blueprint $blueprint, Fluent $command, Connection $connection)
    {
        $schema = $connection->getDoctrineSchemaManager();
        $tableDiff = $this->getDoctrineTableDiff($blueprint, $schema);
        foreach ($command->columns as $name) {
            $column = $connection->getDoctrineColumn($blueprint->getTable(), $name);
            $tableDiff->removedColumns[$name] = $column;
        }
        return (array) $schema->getDatabasePlatform()->getAlterTableSQL($tableDiff);
    }
    public function compileDropUnique(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "drop index {$index}";
    }
    public function compileDropIndex(Blueprint $blueprint, Fluent $command)
    {
        $index = $this->wrap($command->index);
        return "drop index {$index}";
    }
    public function compileRename(Blueprint $blueprint, Fluent $command)
    {
        $from = $this->wrapTable($blueprint);
        return "alter table {$from} rename to " . $this->wrapTable($command->to);
    }
    public function compileEnableForeignKeyConstraints()
    {
        return 'PRAGMA foreign_keys = ON;';
    }
    public function compileDisableForeignKeyConstraints()
    {
        return 'PRAGMA foreign_keys = OFF;';
    }
    protected function typeChar(Fluent $column)
    {
        return 'varchar';
    }
    protected function typeString(Fluent $column)
    {
        return 'varchar';
    }
    protected function typeText(Fluent $column)
    {
        return 'text';
    }
    protected function typeMediumText(Fluent $column)
    {
        return 'text';
    }
    protected function typeLongText(Fluent $column)
    {
        return 'text';
    }
    protected function typeInteger(Fluent $column)
    {
        return 'integer';
    }
    protected function typeBigInteger(Fluent $column)
    {
        return 'integer';
    }
    protected function typeMediumInteger(Fluent $column)
    {
        return 'integer';
    }
    protected function typeTinyInteger(Fluent $column)
    {
        return 'integer';
    }
    protected function typeSmallInteger(Fluent $column)
    {
        return 'integer';
    }
    protected function typeFloat(Fluent $column)
    {
        return 'float';
    }
    protected function typeDouble(Fluent $column)
    {
        return 'float';
    }
    protected function typeDecimal(Fluent $column)
    {
        return 'numeric';
    }
    protected function typeBoolean(Fluent $column)
    {
        return 'tinyint(1)';
    }
    protected function typeEnum(Fluent $column)
    {
        return 'varchar';
    }
    protected function typeJson(Fluent $column)
    {
        return 'text';
    }
    protected function typeJsonb(Fluent $column)
    {
        return 'text';
    }
    protected function typeDate(Fluent $column)
    {
        return 'date';
    }
    protected function typeDateTime(Fluent $column)
    {
        return 'datetime';
    }
    protected function typeDateTimeTz(Fluent $column)
    {
        return 'datetime';
    }
    protected function typeTime(Fluent $column)
    {
        return 'time';
    }
    protected function typeTimeTz(Fluent $column)
    {
        return 'time';
    }
    protected function typeTimestamp(Fluent $column)
    {
        if ($column->useCurrent) {
            return 'datetime default CURRENT_TIMESTAMP';
        }
        return 'datetime';
    }
    protected function typeTimestampTz(Fluent $column)
    {
        if ($column->useCurrent) {
            return 'datetime default CURRENT_TIMESTAMP';
        }
        return 'datetime';
    }
    protected function typeBinary(Fluent $column)
    {
        return 'blob';
    }
    protected function typeUuid(Fluent $column)
    {
        return 'varchar';
    }
    protected function typeIpAddress(Fluent $column)
    {
        return 'varchar';
    }
    protected function typeMacAddress(Fluent $column)
    {
        return 'varchar';
    }
    protected function modifyNullable(Blueprint $blueprint, Fluent $column)
    {
        return $column->nullable ? ' null' : ' not null';
    }
    protected function modifyDefault(Blueprint $blueprint, Fluent $column)
    {
        if (!is_null($column->default)) {
            return ' default ' . $this->getDefaultValue($column->default);
        }
    }
    protected function modifyIncrement(Blueprint $blueprint, Fluent $column)
    {
        if (in_array($column->type, $this->serials) && $column->autoIncrement) {
            return ' primary key autoincrement';
        }
    }
}
}

namespace Illuminate\Database\Schema {
class MySqlBuilder extends Builder
{
    public function hasTable($table)
    {
        $sql = $this->grammar->compileTableExists();
        $database = $this->connection->getDatabaseName();
        $table = $this->connection->getTablePrefix() . $table;
        return count($this->connection->select($sql, [$database, $table])) > 0;
    }
    public function getColumnListing($table)
    {
        $sql = $this->grammar->compileColumnExists();
        $database = $this->connection->getDatabaseName();
        $table = $this->connection->getTablePrefix() . $table;
        $results = $this->connection->select($sql, [$database, $table]);
        return $this->connection->getPostProcessor()->processColumnListing($results);
    }
}
}

namespace Illuminate\Database\Schema {
class PostgresBuilder extends Builder
{
    public function hasTable($table)
    {
        $sql = $this->grammar->compileTableExists();
        $schema = $this->connection->getConfig('schema');
        if (is_array($schema)) {
            $schema = head($schema);
        }
        $table = $this->connection->getTablePrefix() . $table;
        return count($this->connection->select($sql, [$schema, $table])) > 0;
    }
}
}

namespace Illuminate\Database {
interface ConnectionResolverInterface
{
    public function connection($name = null);
    public function getDefaultConnection();
    public function setDefaultConnection($name);
}
}

namespace Illuminate\Database\Capsule {
use PDO;
use Illuminate\Container\Container;
use Illuminate\Database\DatabaseManager;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Traits\CapsuleManagerTrait;
use Illuminate\Database\Eloquent\Model as Eloquent;
use Illuminate\Database\Connectors\ConnectionFactory;
class Manager
{
    use CapsuleManagerTrait;
    protected $manager;
    public function __construct(Container $container = null)
    {
        $this->setupContainer($container ?: new Container());
        $this->setupDefaultConfiguration();
        $this->setupManager();
    }
    protected function setupDefaultConfiguration()
    {
        $this->container['config']['database.fetch'] = PDO::FETCH_OBJ;
        $this->container['config']['database.default'] = 'default';
    }
    protected function setupManager()
    {
        $factory = new ConnectionFactory($this->container);
        $this->manager = new DatabaseManager($this->container, $factory);
    }
    public static function connection($connection = null)
    {
        return static::$instance->getConnection($connection);
    }
    public static function table($table, $connection = null)
    {
        return static::$instance->connection($connection)->table($table);
    }
    public static function schema($connection = null)
    {
        return static::$instance->connection($connection)->getSchemaBuilder();
    }
    public function getConnection($name = null)
    {
        return $this->manager->connection($name);
    }
    public function addConnection(array $config, $name = 'default')
    {
        $connections = $this->container['config']['database.connections'];
        $connections[$name] = $config;
        $this->container['config']['database.connections'] = $connections;
    }
    public function bootEloquent()
    {
        Eloquent::setConnectionResolver($this->manager);
        if ($dispatcher = $this->getEventDispatcher()) {
            Eloquent::setEventDispatcher($dispatcher);
        }
    }
    public function setFetchMode($fetchMode)
    {
        $this->container['config']['database.fetch'] = $fetchMode;
        return $this;
    }
    public function getDatabaseManager()
    {
        return $this->manager;
    }
    public function getEventDispatcher()
    {
        if ($this->container->bound('events')) {
            return $this->container['events'];
        }
    }
    public function setEventDispatcher(Dispatcher $dispatcher)
    {
        $this->container->instance('events', $dispatcher);
    }
    public static function __callStatic($method, $parameters)
    {
        return static::connection()->{$method}(...$parameters);
    }
}
}

namespace Illuminate\Database {
use Closure;
use Exception;
use Throwable;
use Doctrine\DBAL\Driver\PDOSqlsrv\Driver as DoctrineDriver;
use Illuminate\Database\Query\Processors\SqlServerProcessor;
use Illuminate\Database\Query\Grammars\SqlServerGrammar as QueryGrammar;
use Illuminate\Database\Schema\Grammars\SqlServerGrammar as SchemaGrammar;
class SqlServerConnection extends Connection
{
    public function transaction(Closure $callback, $attempts = 1)
    {
        for ($a = 1; $a <= $attempts; $a++) {
            if ($this->getDriverName() == 'sqlsrv') {
                return parent::transaction($callback);
            }
            $this->getPdo()->exec('BEGIN TRAN');
            try {
                $result = $callback($this);
                $this->getPdo()->exec('COMMIT TRAN');
            } catch (Exception $e) {
                $this->getPdo()->exec('ROLLBACK TRAN');
                throw $e;
            } catch (Throwable $e) {
                $this->getPdo()->exec('ROLLBACK TRAN');
                throw $e;
            }
            return $result;
        }
    }
    protected function getDefaultQueryGrammar()
    {
        return $this->withTablePrefix(new QueryGrammar());
    }
    protected function getDefaultSchemaGrammar()
    {
        return $this->withTablePrefix(new SchemaGrammar());
    }
    protected function getDefaultPostProcessor()
    {
        return new SqlServerProcessor();
    }
    protected function getDoctrineDriver()
    {
        return new DoctrineDriver();
    }
}
}

namespace Illuminate\Database\Eloquent {
use Closure;
use Faker\Generator as Faker;
use InvalidArgumentException;
class FactoryBuilder
{
    protected $definitions;
    protected $class;
    protected $name = 'default';
    protected $amount = 1;
    protected $faker;
    public function __construct($class, $name, array $definitions, Faker $faker)
    {
        $this->name = $name;
        $this->class = $class;
        $this->faker = $faker;
        $this->definitions = $definitions;
    }
    public function times($amount)
    {
        $this->amount = $amount;
        return $this;
    }
    public function create(array $attributes = [])
    {
        $results = $this->make($attributes);
        if ($this->amount === 1) {
            $results->save();
        } else {
            foreach ($results as $result) {
                $result->save();
            }
        }
        return $results;
    }
    public function make(array $attributes = [])
    {
        if ($this->amount === 1) {
            return $this->makeInstance($attributes);
        }
        return new Collection(array_map(function () use($attributes) {
            return $this->makeInstance($attributes);
        }, range(1, $this->amount)));
    }
    protected function makeInstance(array $attributes = [])
    {
        return Model::unguarded(function () use($attributes) {
            if (!isset($this->definitions[$this->class][$this->name])) {
                throw new InvalidArgumentException("Unable to locate factory with name [{$this->name}] [{$this->class}].");
            }
            $definition = call_user_func($this->definitions[$this->class][$this->name], $this->faker, $attributes);
            $evaluated = $this->callClosureAttributes(array_merge($definition, $attributes));
            return new $this->class($evaluated);
        });
    }
    protected function callClosureAttributes(array $attributes)
    {
        foreach ($attributes as &$attribute) {
            $attribute = $attribute instanceof Closure ? $attribute($attributes) : $attribute;
        }
        return $attributes;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use BadMethodCallException;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
class MorphTo extends BelongsTo
{
    protected $morphType;
    protected $models;
    protected $dictionary = [];
    protected $macroBuffer = [];
    public function __construct(Builder $query, Model $parent, $foreignKey, $otherKey, $type, $relation)
    {
        $this->morphType = $type;
        parent::__construct($query, $parent, $foreignKey, $otherKey, $relation);
    }
    public function getResults()
    {
        if (!$this->otherKey) {
            return;
        }
        return $this->query->first();
    }
    public function addEagerConstraints(array $models)
    {
        $this->buildDictionary($this->models = Collection::make($models));
    }
    protected function buildDictionary(Collection $models)
    {
        foreach ($models as $model) {
            if ($model->{$this->morphType}) {
                $this->dictionary[$model->{$this->morphType}][$model->{$this->foreignKey}][] = $model;
            }
        }
    }
    public function match(array $models, Collection $results, $relation)
    {
        return $models;
    }
    public function associate($model)
    {
        $this->parent->setAttribute($this->foreignKey, $model->getKey());
        $this->parent->setAttribute($this->morphType, $model->getMorphClass());
        return $this->parent->setRelation($this->relation, $model);
    }
    public function dissociate()
    {
        $this->parent->setAttribute($this->foreignKey, null);
        $this->parent->setAttribute($this->morphType, null);
        return $this->parent->setRelation($this->relation, null);
    }
    public function getEager()
    {
        foreach (array_keys($this->dictionary) as $type) {
            $this->matchToMorphParents($type, $this->getResultsByType($type));
        }
        return $this->models;
    }
    protected function matchToMorphParents($type, Collection $results)
    {
        foreach ($results as $result) {
            if (isset($this->dictionary[$type][$result->getKey()])) {
                foreach ($this->dictionary[$type][$result->getKey()] as $model) {
                    $model->setRelation($this->relation, $result);
                }
            }
        }
    }
    protected function getResultsByType($type)
    {
        $instance = $this->createModelByType($type);
        $key = $instance->getTable() . '.' . $instance->getKeyName();
        $query = $this->replayMacros($instance->newQuery())->mergeModelDefinedRelationConstraints($this->getQuery())->with($this->getQuery()->getEagerLoads());
        return $query->whereIn($key, $this->gatherKeysByType($type)->all())->get();
    }
    protected function gatherKeysByType($type)
    {
        $foreign = $this->foreignKey;
        return collect($this->dictionary[$type])->map(function ($models) use($foreign) {
            return head($models)->{$foreign};
        })->values()->unique();
    }
    public function createModelByType($type)
    {
        $class = $this->parent->getActualClassNameForMorph($type);
        return new $class();
    }
    public function getMorphType()
    {
        return $this->morphType;
    }
    public function getDictionary()
    {
        return $this->dictionary;
    }
    protected function replayMacros(Builder $query)
    {
        foreach ($this->macroBuffer as $macro) {
            call_user_func_array([$query, $macro['method']], $macro['parameters']);
        }
        return $query;
    }
    public function __call($method, $parameters)
    {
        try {
            return parent::__call($method, $parameters);
        } catch (BadMethodCallException $e) {
            $this->macroBuffer[] = compact('method', 'parameters');
            return $this;
        }
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Database\Eloquent\ModelNotFoundException;
class HasManyThrough extends Relation
{
    protected $farParent;
    protected $firstKey;
    protected $secondKey;
    protected $localKey;
    public function __construct(Builder $query, Model $farParent, Model $parent, $firstKey, $secondKey, $localKey)
    {
        $this->localKey = $localKey;
        $this->firstKey = $firstKey;
        $this->secondKey = $secondKey;
        $this->farParent = $farParent;
        parent::__construct($query, $parent);
    }
    public function addConstraints()
    {
        $parentTable = $this->parent->getTable();
        $localValue = $this->farParent[$this->localKey];
        $this->setJoin();
        if (static::$constraints) {
            $this->query->where($parentTable . '.' . $this->firstKey, '=', $localValue);
        }
    }
    public function getRelationQuery(Builder $query, Builder $parent, $columns = ['*'])
    {
        $parentTable = $this->parent->getTable();
        $this->setJoin($query);
        $query->select($columns);
        $key = $this->wrap($parentTable . '.' . $this->firstKey);
        return $query->where($this->getHasCompareKey(), '=', new Expression($key));
    }
    protected function setJoin(Builder $query = null)
    {
        $query = $query ?: $this->query;
        $foreignKey = $this->related->getTable() . '.' . $this->secondKey;
        $query->join($this->parent->getTable(), $this->getQualifiedParentKeyName(), '=', $foreignKey);
        if ($this->parentSoftDeletes()) {
            $query->whereNull($this->parent->getQualifiedDeletedAtColumn());
        }
    }
    public function parentSoftDeletes()
    {
        return in_array(SoftDeletes::class, class_uses_recursive(get_class($this->parent)));
    }
    public function addEagerConstraints(array $models)
    {
        $table = $this->parent->getTable();
        $this->query->whereIn($table . '.' . $this->firstKey, $this->getKeys($models, $this->localKey));
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->related->newCollection());
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        $dictionary = $this->buildDictionary($results);
        foreach ($models as $model) {
            $key = $model->getKey();
            if (isset($dictionary[$key])) {
                $value = $this->related->newCollection($dictionary[$key]);
                $model->setRelation($relation, $value);
            }
        }
        return $models;
    }
    protected function buildDictionary(Collection $results)
    {
        $dictionary = [];
        $foreign = $this->firstKey;
        foreach ($results as $result) {
            $dictionary[$result->{$foreign}][] = $result;
        }
        return $dictionary;
    }
    public function getResults()
    {
        return $this->get();
    }
    public function first($columns = ['*'])
    {
        $results = $this->take(1)->get($columns);
        return count($results) > 0 ? $results->first() : null;
    }
    public function firstOrFail($columns = ['*'])
    {
        if (!is_null($model = $this->first($columns))) {
            return $model;
        }
        throw (new ModelNotFoundException())->setModel(get_class($this->parent));
    }
    public function find($id, $columns = ['*'])
    {
        if (is_array($id)) {
            return $this->findMany($id, $columns);
        }
        $this->where($this->getRelated()->getQualifiedKeyName(), '=', $id);
        return $this->first($columns);
    }
    public function findMany($ids, $columns = ['*'])
    {
        if (empty($ids)) {
            return $this->getRelated()->newCollection();
        }
        $this->whereIn($this->getRelated()->getQualifiedKeyName(), $ids);
        return $this->get($columns);
    }
    public function findOrFail($id, $columns = ['*'])
    {
        $result = $this->find($id, $columns);
        if (is_array($id)) {
            if (count($result) == count(array_unique($id))) {
                return $result;
            }
        } elseif (!is_null($result)) {
            return $result;
        }
        throw (new ModelNotFoundException())->setModel(get_class($this->parent));
    }
    public function get($columns = ['*'])
    {
        $columns = $this->query->getQuery()->columns ? [] : $columns;
        $select = $this->getSelectColumns($columns);
        $builder = $this->query->applyScopes();
        $models = $builder->addSelect($select)->getModels();
        if (count($models) > 0) {
            $models = $builder->eagerLoadRelations($models);
        }
        return $this->related->newCollection($models);
    }
    protected function getSelectColumns(array $columns = ['*'])
    {
        if ($columns == ['*']) {
            $columns = [$this->related->getTable() . '.*'];
        }
        return array_merge($columns, [$this->parent->getTable() . '.' . $this->firstKey]);
    }
    public function paginate($perPage = null, $columns = ['*'], $pageName = 'page', $page = null)
    {
        $this->query->addSelect($this->getSelectColumns($columns));
        return $this->query->paginate($perPage, $columns, $pageName, $page);
    }
    public function simplePaginate($perPage = null, $columns = ['*'], $pageName = 'page')
    {
        $this->query->addSelect($this->getSelectColumns($columns));
        return $this->query->simplePaginate($perPage, $columns, $pageName);
    }
    public function getHasCompareKey()
    {
        return $this->farParent->getQualifiedKeyName();
    }
    public function getForeignKey()
    {
        return $this->related->getTable() . '.' . $this->secondKey;
    }
    public function getThroughKey()
    {
        return $this->parent->getTable() . '.' . $this->firstKey;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Closure;
use Illuminate\Support\Arr;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Eloquent\Collection;
abstract class Relation
{
    protected $query;
    protected $parent;
    protected $related;
    protected static $constraints = true;
    protected static $morphMap = [];
    public function __construct(Builder $query, Model $parent)
    {
        $this->query = $query;
        $this->parent = $parent;
        $this->related = $query->getModel();
        $this->addConstraints();
    }
    public abstract function addConstraints();
    public abstract function addEagerConstraints(array $models);
    public abstract function initRelation(array $models, $relation);
    public abstract function match(array $models, Collection $results, $relation);
    public abstract function getResults();
    public function getEager()
    {
        return $this->get();
    }
    public function touch()
    {
        $column = $this->getRelated()->getUpdatedAtColumn();
        $this->rawUpdate([$column => $this->getRelated()->freshTimestampString()]);
    }
    public function rawUpdate(array $attributes = [])
    {
        return $this->query->update($attributes);
    }
    public function getRelationCountQuery(Builder $query, Builder $parent)
    {
        return $this->getRelationQuery($query, $parent, new Expression('count(*)'));
    }
    public function getRelationQuery(Builder $query, Builder $parent, $columns = ['*'])
    {
        $query->select($columns);
        $key = $this->wrap($this->getQualifiedParentKeyName());
        return $query->where($this->getHasCompareKey(), '=', new Expression($key));
    }
    public static function noConstraints(Closure $callback)
    {
        $previous = static::$constraints;
        static::$constraints = false;
        try {
            $results = call_user_func($callback);
        } finally {
            static::$constraints = $previous;
        }
        return $results;
    }
    protected function getKeys(array $models, $key = null)
    {
        return array_unique(array_values(array_map(function ($value) use($key) {
            return $key ? $value->getAttribute($key) : $value->getKey();
        }, $models)));
    }
    public function getQuery()
    {
        return $this->query;
    }
    public function getBaseQuery()
    {
        return $this->query->getQuery();
    }
    public function getParent()
    {
        return $this->parent;
    }
    public function getQualifiedParentKeyName()
    {
        return $this->parent->getQualifiedKeyName();
    }
    public function getRelated()
    {
        return $this->related;
    }
    public function createdAt()
    {
        return $this->parent->getCreatedAtColumn();
    }
    public function updatedAt()
    {
        return $this->parent->getUpdatedAtColumn();
    }
    public function relatedUpdatedAt()
    {
        return $this->related->getUpdatedAtColumn();
    }
    public function wrap($value)
    {
        return $this->parent->newQueryWithoutScopes()->getQuery()->getGrammar()->wrap($value);
    }
    public static function morphMap(array $map = null, $merge = true)
    {
        $map = static::buildMorphMapFromModels($map);
        if (is_array($map)) {
            static::$morphMap = $merge && static::$morphMap ? array_merge(static::$morphMap, $map) : $map;
        }
        return static::$morphMap;
    }
    protected static function buildMorphMapFromModels(array $models = null)
    {
        if (is_null($models) || Arr::isAssoc($models)) {
            return $models;
        }
        $tables = array_map(function ($model) {
            return (new $model())->getTable();
        }, $models);
        return array_combine($tables, $models);
    }
    public function __call($method, $parameters)
    {
        $result = call_user_func_array([$this->query, $method], $parameters);
        if ($result === $this->query) {
            return $this;
        }
        return $result;
    }
    public function __clone()
    {
        $this->query = clone $this->query;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Eloquent\Collection;
abstract class HasOneOrMany extends Relation
{
    protected $foreignKey;
    protected $localKey;
    protected static $selfJoinCount = 0;
    public function __construct(Builder $query, Model $parent, $foreignKey, $localKey)
    {
        $this->localKey = $localKey;
        $this->foreignKey = $foreignKey;
        parent::__construct($query, $parent);
    }
    public function addConstraints()
    {
        if (static::$constraints) {
            $this->query->where($this->foreignKey, '=', $this->getParentKey());
            $this->query->whereNotNull($this->foreignKey);
        }
    }
    public function getRelationQuery(Builder $query, Builder $parent, $columns = ['*'])
    {
        if ($parent->getQuery()->from == $query->getQuery()->from) {
            return $this->getRelationQueryForSelfRelation($query, $parent, $columns);
        }
        return parent::getRelationQuery($query, $parent, $columns);
    }
    public function getRelationQueryForSelfRelation(Builder $query, Builder $parent, $columns = ['*'])
    {
        $query->select($columns);
        $query->from($query->getModel()->getTable() . ' as ' . ($hash = $this->getRelationCountHash()));
        $query->getModel()->setTable($hash);
        $key = $this->wrap($this->getQualifiedParentKeyName());
        return $query->where($hash . '.' . $this->getPlainForeignKey(), '=', new Expression($key));
    }
    public function getRelationCountHash()
    {
        return 'laravel_reserved_' . static::$selfJoinCount++;
    }
    public function addEagerConstraints(array $models)
    {
        $this->query->whereIn($this->foreignKey, $this->getKeys($models, $this->localKey));
    }
    public function matchOne(array $models, Collection $results, $relation)
    {
        return $this->matchOneOrMany($models, $results, $relation, 'one');
    }
    public function matchMany(array $models, Collection $results, $relation)
    {
        return $this->matchOneOrMany($models, $results, $relation, 'many');
    }
    protected function matchOneOrMany(array $models, Collection $results, $relation, $type)
    {
        $dictionary = $this->buildDictionary($results);
        foreach ($models as $model) {
            $key = $model->getAttribute($this->localKey);
            if (isset($dictionary[$key])) {
                $value = $this->getRelationValue($dictionary, $key, $type);
                $model->setRelation($relation, $value);
            }
        }
        return $models;
    }
    protected function getRelationValue(array $dictionary, $key, $type)
    {
        $value = $dictionary[$key];
        return $type == 'one' ? reset($value) : $this->related->newCollection($value);
    }
    protected function buildDictionary(Collection $results)
    {
        $dictionary = [];
        $foreign = $this->getPlainForeignKey();
        foreach ($results as $result) {
            $dictionary[$result->{$foreign}][] = $result;
        }
        return $dictionary;
    }
    public function save(Model $model)
    {
        $model->setAttribute($this->getPlainForeignKey(), $this->getParentKey());
        return $model->save() ? $model : false;
    }
    public function saveMany($models)
    {
        foreach ($models as $model) {
            $this->save($model);
        }
        return $models;
    }
    public function findOrNew($id, $columns = ['*'])
    {
        if (is_null($instance = $this->find($id, $columns))) {
            $instance = $this->related->newInstance();
            $instance->setAttribute($this->getPlainForeignKey(), $this->getParentKey());
        }
        return $instance;
    }
    public function firstOrNew(array $attributes)
    {
        if (is_null($instance = $this->where($attributes)->first())) {
            $instance = $this->related->newInstance($attributes);
            $instance->setAttribute($this->getPlainForeignKey(), $this->getParentKey());
        }
        return $instance;
    }
    public function firstOrCreate(array $attributes)
    {
        if (is_null($instance = $this->where($attributes)->first())) {
            $instance = $this->create($attributes);
        }
        return $instance;
    }
    public function updateOrCreate(array $attributes, array $values = [])
    {
        $instance = $this->firstOrNew($attributes);
        $instance->fill($values);
        $instance->save();
        return $instance;
    }
    public function create(array $attributes)
    {
        $instance = $this->related->newInstance($attributes);
        $instance->setAttribute($this->getPlainForeignKey(), $this->getParentKey());
        $instance->save();
        return $instance;
    }
    public function createMany(array $records)
    {
        $instances = [];
        foreach ($records as $record) {
            $instances[] = $this->create($record);
        }
        return $instances;
    }
    public function update(array $attributes)
    {
        if ($this->related->usesTimestamps()) {
            $attributes[$this->relatedUpdatedAt()] = $this->related->freshTimestampString();
        }
        return $this->query->update($attributes);
    }
    public function getHasCompareKey()
    {
        return $this->getForeignKey();
    }
    public function getForeignKey()
    {
        return $this->foreignKey;
    }
    public function getPlainForeignKey()
    {
        $segments = explode('.', $this->getForeignKey());
        return $segments[count($segments) - 1];
    }
    public function getParentKey()
    {
        return $this->parent->getAttribute($this->localKey);
    }
    public function getQualifiedParentKeyName()
    {
        return $this->parent->getTable() . '.' . $this->localKey;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Collection;
class MorphMany extends MorphOneOrMany
{
    public function getResults()
    {
        return $this->query->get();
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->related->newCollection());
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        return $this->matchMany($models, $results, $relation);
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
class Pivot extends Model
{
    protected $parent;
    protected $foreignKey;
    protected $otherKey;
    protected $guarded = [];
    public function __construct(Model $parent, $attributes, $table, $exists = false)
    {
        parent::__construct();
        $this->setTable($table);
        $this->setConnection($parent->getConnectionName());
        $this->forceFill($attributes);
        $this->syncOriginal();
        $this->parent = $parent;
        $this->exists = $exists;
        $this->timestamps = $this->hasTimestampAttributes();
    }
    public static function fromRawAttributes(Model $parent, $attributes, $table, $exists = false)
    {
        $instance = new static($parent, $attributes, $table, $exists);
        $instance->setRawAttributes($attributes, true);
        return $instance;
    }
    protected function setKeysForSaveQuery(Builder $query)
    {
        $query->where($this->foreignKey, $this->getAttribute($this->foreignKey));
        return $query->where($this->otherKey, $this->getAttribute($this->otherKey));
    }
    public function delete()
    {
        return $this->getDeleteQuery()->delete();
    }
    protected function getDeleteQuery()
    {
        $foreign = $this->getAttribute($this->foreignKey);
        $query = $this->newQuery()->where($this->foreignKey, $foreign);
        return $query->where($this->otherKey, $this->getAttribute($this->otherKey));
    }
    public function getForeignKey()
    {
        return $this->foreignKey;
    }
    public function getOtherKey()
    {
        return $this->otherKey;
    }
    public function setPivotKeys($foreignKey, $otherKey)
    {
        $this->foreignKey = $foreignKey;
        $this->otherKey = $otherKey;
        return $this;
    }
    public function hasTimestampAttributes()
    {
        return array_key_exists($this->getCreatedAtColumn(), $this->attributes);
    }
    public function getCreatedAtColumn()
    {
        return $this->parent->getCreatedAtColumn();
    }
    public function getUpdatedAtColumn()
    {
        return $this->parent->getUpdatedAtColumn();
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Collection;
class MorphOne extends MorphOneOrMany
{
    public function getResults()
    {
        return $this->query->first();
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, null);
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        return $this->matchOne($models, $results, $relation);
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Collection;
class HasMany extends HasOneOrMany
{
    public function getResults()
    {
        return $this->query->get();
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->related->newCollection());
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        return $this->matchMany($models, $results, $relation);
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Support\Arr;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
class MorphToMany extends BelongsToMany
{
    protected $morphType;
    protected $morphClass;
    protected $inverse;
    public function __construct(Builder $query, Model $parent, $name, $table, $foreignKey, $otherKey, $relationName = null, $inverse = false)
    {
        $this->inverse = $inverse;
        $this->morphType = $name . '_type';
        $this->morphClass = $inverse ? $query->getModel()->getMorphClass() : $parent->getMorphClass();
        parent::__construct($query, $parent, $table, $foreignKey, $otherKey, $relationName);
    }
    protected function setWhere()
    {
        parent::setWhere();
        $this->query->where($this->table . '.' . $this->morphType, $this->morphClass);
        return $this;
    }
    public function getRelationQuery(Builder $query, Builder $parent, $columns = ['*'])
    {
        $query = parent::getRelationQuery($query, $parent, $columns);
        return $query->where($this->table . '.' . $this->morphType, $this->morphClass);
    }
    public function addEagerConstraints(array $models)
    {
        parent::addEagerConstraints($models);
        $this->query->where($this->table . '.' . $this->morphType, $this->morphClass);
    }
    protected function createAttachRecord($id, $timed)
    {
        $record = parent::createAttachRecord($id, $timed);
        return Arr::add($record, $this->morphType, $this->morphClass);
    }
    protected function newPivotQuery()
    {
        $query = parent::newPivotQuery();
        return $query->where($this->morphType, $this->morphClass);
    }
    public function newPivot(array $attributes = [], $exists = false)
    {
        $pivot = new MorphPivot($this->parent, $attributes, $this->table, $exists);
        $pivot->setPivotKeys($this->foreignKey, $this->otherKey)->setMorphType($this->morphType)->setMorphClass($this->morphClass);
        return $pivot;
    }
    public function getMorphType()
    {
        return $this->morphType;
    }
    public function getMorphClass()
    {
        return $this->morphClass;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
abstract class MorphOneOrMany extends HasOneOrMany
{
    protected $morphType;
    protected $morphClass;
    public function __construct(Builder $query, Model $parent, $type, $id, $localKey)
    {
        $this->morphType = $type;
        $this->morphClass = $parent->getMorphClass();
        parent::__construct($query, $parent, $id, $localKey);
    }
    public function addConstraints()
    {
        if (static::$constraints) {
            parent::addConstraints();
            $this->query->where($this->morphType, $this->morphClass);
        }
    }
    public function getRelationQuery(Builder $query, Builder $parent, $columns = ['*'])
    {
        $query = parent::getRelationQuery($query, $parent, $columns);
        return $query->where($this->morphType, $this->morphClass);
    }
    public function addEagerConstraints(array $models)
    {
        parent::addEagerConstraints($models);
        $this->query->where($this->morphType, $this->morphClass);
    }
    public function save(Model $model)
    {
        $model->setAttribute($this->getPlainMorphType(), $this->morphClass);
        return parent::save($model);
    }
    public function findOrNew($id, $columns = ['*'])
    {
        if (is_null($instance = $this->find($id, $columns))) {
            $instance = $this->related->newInstance();
            $this->setForeignAttributesForCreate($instance);
        }
        return $instance;
    }
    public function firstOrNew(array $attributes)
    {
        if (is_null($instance = $this->where($attributes)->first())) {
            $instance = $this->related->newInstance($attributes);
            $this->setForeignAttributesForCreate($instance);
        }
        return $instance;
    }
    public function firstOrCreate(array $attributes)
    {
        if (is_null($instance = $this->where($attributes)->first())) {
            $instance = $this->create($attributes);
        }
        return $instance;
    }
    public function updateOrCreate(array $attributes, array $values = [])
    {
        $instance = $this->firstOrNew($attributes);
        $instance->fill($values);
        $instance->save();
        return $instance;
    }
    public function create(array $attributes)
    {
        $instance = $this->related->newInstance($attributes);
        $this->setForeignAttributesForCreate($instance);
        $instance->save();
        return $instance;
    }
    protected function setForeignAttributesForCreate(Model $model)
    {
        $model->{$this->getPlainForeignKey()} = $this->getParentKey();
        $model->{last(explode('.', $this->morphType))} = $this->morphClass;
    }
    public function getMorphType()
    {
        return $this->morphType;
    }
    public function getPlainMorphType()
    {
        return last(explode('.', $this->morphType));
    }
    public function getMorphClass()
    {
        return $this->morphClass;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Builder;
class MorphPivot extends Pivot
{
    protected $morphType;
    protected $morphClass;
    protected function setKeysForSaveQuery(Builder $query)
    {
        $query->where($this->morphType, $this->morphClass);
        return parent::setKeysForSaveQuery($query);
    }
    public function delete()
    {
        $query = $this->getDeleteQuery();
        $query->where($this->morphType, $this->morphClass);
        return $query->delete();
    }
    public function setMorphType($morphType)
    {
        $this->morphType = $morphType;
        return $this;
    }
    public function setMorphClass($morphClass)
    {
        $this->morphClass = $morphClass;
        return $this;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Collection;
class HasOne extends HasOneOrMany
{
    public function getResults()
    {
        return $this->query->first();
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, null);
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        return $this->matchOne($models, $results, $relation);
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\Eloquent\Collection;
class BelongsTo extends Relation
{
    protected $foreignKey;
    protected $otherKey;
    protected $relation;
    protected static $selfJoinCount = 0;
    public function __construct(Builder $query, Model $parent, $foreignKey, $otherKey, $relation)
    {
        $this->otherKey = $otherKey;
        $this->relation = $relation;
        $this->foreignKey = $foreignKey;
        parent::__construct($query, $parent);
    }
    public function getResults()
    {
        return $this->query->first();
    }
    public function addConstraints()
    {
        if (static::$constraints) {
            $table = $this->related->getTable();
            $this->query->where($table . '.' . $this->otherKey, '=', $this->parent->{$this->foreignKey});
        }
    }
    public function getRelationQuery(Builder $query, Builder $parent, $columns = ['*'])
    {
        if ($parent->getQuery()->from == $query->getQuery()->from) {
            return $this->getRelationQueryForSelfRelation($query, $parent, $columns);
        }
        $query->select($columns);
        $otherKey = $this->wrap($query->getModel()->getTable() . '.' . $this->otherKey);
        return $query->where($this->getQualifiedForeignKey(), '=', new Expression($otherKey));
    }
    public function getRelationQueryForSelfRelation(Builder $query, Builder $parent, $columns = ['*'])
    {
        $query->select($columns);
        $query->from($query->getModel()->getTable() . ' as ' . ($hash = $this->getRelationCountHash()));
        $query->getModel()->setTable($hash);
        $key = $this->wrap($this->getQualifiedForeignKey());
        return $query->where($hash . '.' . $query->getModel()->getKeyName(), '=', new Expression($key));
    }
    public function getRelationCountHash()
    {
        return 'laravel_reserved_' . static::$selfJoinCount++;
    }
    public function addEagerConstraints(array $models)
    {
        $key = $this->related->getTable() . '.' . $this->otherKey;
        $this->query->whereIn($key, $this->getEagerModelKeys($models));
    }
    protected function getEagerModelKeys(array $models)
    {
        $keys = [];
        foreach ($models as $model) {
            if (!is_null($value = $model->{$this->foreignKey})) {
                $keys[] = $value;
            }
        }
        if (count($keys) === 0) {
            return [$this->related->getIncrementing() ? 0 : null];
        }
        return array_values(array_unique($keys));
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, null);
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        $foreign = $this->foreignKey;
        $other = $this->otherKey;
        $dictionary = [];
        foreach ($results as $result) {
            $dictionary[$result->getAttribute($other)] = $result;
        }
        foreach ($models as $model) {
            if (isset($dictionary[$model->{$foreign}])) {
                $model->setRelation($relation, $dictionary[$model->{$foreign}]);
            }
        }
        return $models;
    }
    public function associate($model)
    {
        $otherKey = $model instanceof Model ? $model->getAttribute($this->otherKey) : $model;
        $this->parent->setAttribute($this->foreignKey, $otherKey);
        if ($model instanceof Model) {
            $this->parent->setRelation($this->relation, $model);
        }
        return $this->parent;
    }
    public function dissociate()
    {
        $this->parent->setAttribute($this->foreignKey, null);
        return $this->parent->setRelation($this->relation, null);
    }
    public function update(array $attributes)
    {
        $instance = $this->getResults();
        return $instance->fill($attributes)->save();
    }
    public function getForeignKey()
    {
        return $this->foreignKey;
    }
    public function getQualifiedForeignKey()
    {
        return $this->parent->getTable() . '.' . $this->foreignKey;
    }
    public function getOtherKey()
    {
        return $this->otherKey;
    }
    public function getRelation()
    {
        return $this->relation;
    }
    public function getQualifiedOtherKeyName()
    {
        return $this->related->getTable() . '.' . $this->otherKey;
    }
}
}

namespace Illuminate\Database\Eloquent\Relations {
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\ModelNotFoundException;
class BelongsToMany extends Relation
{
    protected $table;
    protected $foreignKey;
    protected $otherKey;
    protected $relationName;
    protected $pivotColumns = [];
    protected $pivotWheres = [];
    protected $pivotWhereIns = [];
    protected $pivotCreatedAt;
    protected $pivotUpdatedAt;
    protected static $selfJoinCount = 0;
    public function __construct(Builder $query, Model $parent, $table, $foreignKey, $otherKey, $relationName = null)
    {
        $this->table = $table;
        $this->otherKey = $otherKey;
        $this->foreignKey = $foreignKey;
        $this->relationName = $relationName;
        parent::__construct($query, $parent);
    }
    public function getResults()
    {
        return $this->get();
    }
    public function wherePivot($column, $operator = null, $value = null, $boolean = 'and')
    {
        $this->pivotWheres[] = func_get_args();
        return $this->where($this->table . '.' . $column, $operator, $value, $boolean);
    }
    public function wherePivotIn($column, $values, $boolean = 'and', $not = false)
    {
        $this->pivotWhereIns[] = func_get_args();
        return $this->whereIn($this->table . '.' . $column, $values, $boolean, $not);
    }
    public function orWherePivot($column, $operator = null, $value = null)
    {
        return $this->wherePivot($column, $operator, $value, 'or');
    }
    public function orWherePivotIn($column, $values)
    {
        return $this->wherePivotIn($column, $values, 'or');
    }
    public function first($columns = ['*'])
    {
        $results = $this->take(1)->get($columns);
        return count($results) > 0 ? $results->first() : null;
    }
    public function firstOrFail($columns = ['*'])
    {
        if (!is_null($model = $this->first($columns))) {
            return $model;
        }
        throw (new ModelNotFoundException())->setModel(get_class($this->parent));
    }
    public function get($columns = ['*'])
    {
        $columns = $this->query->getQuery()->columns ? [] : $columns;
        $select = $this->getSelectColumns($columns);
        $builder = $this->query->applyScopes();
        $models = $builder->addSelect($select)->getModels();
        $this->hydratePivotRelation($models);
        if (count($models) > 0) {
            $models = $builder->eagerLoadRelations($models);
        }
        return $this->related->newCollection($models);
    }
    public function paginate($perPage = null, $columns = ['*'], $pageName = 'page', $page = null)
    {
        $this->query->addSelect($this->getSelectColumns($columns));
        $paginator = $this->query->paginate($perPage, $columns, $pageName, $page);
        $this->hydratePivotRelation($paginator->items());
        return $paginator;
    }
    public function simplePaginate($perPage = null, $columns = ['*'], $pageName = 'page')
    {
        $this->query->addSelect($this->getSelectColumns($columns));
        $paginator = $this->query->simplePaginate($perPage, $columns, $pageName);
        $this->hydratePivotRelation($paginator->items());
        return $paginator;
    }
    public function chunk($count, callable $callback)
    {
        $this->query->addSelect($this->getSelectColumns());
        return $this->query->chunk($count, function ($results) use($callback) {
            $this->hydratePivotRelation($results->all());
            return $callback($results);
        });
    }
    protected function hydratePivotRelation(array $models)
    {
        foreach ($models as $model) {
            $pivot = $this->newExistingPivot($this->cleanPivotAttributes($model));
            $model->setRelation('pivot', $pivot);
        }
    }
    protected function cleanPivotAttributes(Model $model)
    {
        $values = [];
        foreach ($model->getAttributes() as $key => $value) {
            if (strpos($key, 'pivot_') === 0) {
                $values[substr($key, 6)] = $value;
                unset($model->{$key});
            }
        }
        return $values;
    }
    public function addConstraints()
    {
        $this->setJoin();
        if (static::$constraints) {
            $this->setWhere();
        }
    }
    public function getRelationQuery(Builder $query, Builder $parent, $columns = ['*'])
    {
        if ($parent->getQuery()->from == $query->getQuery()->from) {
            return $this->getRelationQueryForSelfJoin($query, $parent, $columns);
        }
        $this->setJoin($query);
        return parent::getRelationQuery($query, $parent, $columns);
    }
    public function getRelationQueryForSelfJoin(Builder $query, Builder $parent, $columns = ['*'])
    {
        $query->select($columns);
        $query->from($this->related->getTable() . ' as ' . ($hash = $this->getRelationCountHash()));
        $this->related->setTable($hash);
        $this->setJoin($query);
        return parent::getRelationQuery($query, $parent, $columns);
    }
    public function getRelationCountHash()
    {
        return 'laravel_reserved_' . static::$selfJoinCount++;
    }
    protected function getSelectColumns(array $columns = ['*'])
    {
        if ($columns == ['*']) {
            $columns = [$this->related->getTable() . '.*'];
        }
        return array_merge($columns, $this->getAliasedPivotColumns());
    }
    protected function getAliasedPivotColumns()
    {
        $defaults = [$this->foreignKey, $this->otherKey];
        $columns = [];
        foreach (array_merge($defaults, $this->pivotColumns) as $column) {
            $columns[] = $this->table . '.' . $column . ' as pivot_' . $column;
        }
        return array_unique($columns);
    }
    protected function hasPivotColumn($column)
    {
        return in_array($column, $this->pivotColumns);
    }
    protected function setJoin($query = null)
    {
        $query = $query ?: $this->query;
        $baseTable = $this->related->getTable();
        $key = $baseTable . '.' . $this->related->getKeyName();
        $query->join($this->table, $key, '=', $this->getOtherKey());
        return $this;
    }
    protected function setWhere()
    {
        $foreign = $this->getForeignKey();
        $this->query->where($foreign, '=', $this->parent->getKey());
        return $this;
    }
    public function addEagerConstraints(array $models)
    {
        $this->query->whereIn($this->getForeignKey(), $this->getKeys($models));
    }
    public function initRelation(array $models, $relation)
    {
        foreach ($models as $model) {
            $model->setRelation($relation, $this->related->newCollection());
        }
        return $models;
    }
    public function match(array $models, Collection $results, $relation)
    {
        $dictionary = $this->buildDictionary($results);
        foreach ($models as $model) {
            if (isset($dictionary[$key = $model->getKey()])) {
                $collection = $this->related->newCollection($dictionary[$key]);
                $model->setRelation($relation, $collection);
            }
        }
        return $models;
    }
    protected function buildDictionary(Collection $results)
    {
        $foreign = $this->foreignKey;
        $dictionary = [];
        foreach ($results as $result) {
            $dictionary[$result->pivot->{$foreign}][] = $result;
        }
        return $dictionary;
    }
    public function touch()
    {
        $key = $this->getRelated()->getKeyName();
        $columns = $this->getRelatedFreshUpdate();
        $ids = $this->getRelatedIds();
        if (count($ids) > 0) {
            $this->getRelated()->newQuery()->whereIn($key, $ids)->update($columns);
        }
    }
    public function getRelatedIds()
    {
        $related = $this->getRelated();
        $fullKey = $related->getQualifiedKeyName();
        return $this->getQuery()->select($fullKey)->pluck($related->getKeyName());
    }
    public function save(Model $model, array $joining = [], $touch = true)
    {
        $model->save(['touch' => false]);
        $this->attach($model->getKey(), $joining, $touch);
        return $model;
    }
    public function saveMany($models, array $joinings = [])
    {
        foreach ($models as $key => $model) {
            $this->save($model, (array) Arr::get($joinings, $key), false);
        }
        $this->touchIfTouching();
        return $models;
    }
    public function find($id, $columns = ['*'])
    {
        if (is_array($id)) {
            return $this->findMany($id, $columns);
        }
        $this->where($this->getRelated()->getQualifiedKeyName(), '=', $id);
        return $this->first($columns);
    }
    public function findMany($ids, $columns = ['*'])
    {
        if (empty($ids)) {
            return $this->getRelated()->newCollection();
        }
        $this->whereIn($this->getRelated()->getQualifiedKeyName(), $ids);
        return $this->get($columns);
    }
    public function findOrFail($id, $columns = ['*'])
    {
        $result = $this->find($id, $columns);
        if (is_array($id)) {
            if (count($result) == count(array_unique($id))) {
                return $result;
            }
        } elseif (!is_null($result)) {
            return $result;
        }
        throw (new ModelNotFoundException())->setModel(get_class($this->parent));
    }
    public function findOrNew($id, $columns = ['*'])
    {
        if (is_null($instance = $this->find($id, $columns))) {
            $instance = $this->getRelated()->newInstance();
        }
        return $instance;
    }
    public function firstOrNew(array $attributes)
    {
        if (is_null($instance = $this->where($attributes)->first())) {
            $instance = $this->related->newInstance($attributes);
        }
        return $instance;
    }
    public function firstOrCreate(array $attributes, array $joining = [], $touch = true)
    {
        if (is_null($instance = $this->where($attributes)->first())) {
            $instance = $this->create($attributes, $joining, $touch);
        }
        return $instance;
    }
    public function updateOrCreate(array $attributes, array $values = [], array $joining = [], $touch = true)
    {
        if (is_null($instance = $this->where($attributes)->first())) {
            return $this->create($values, $joining, $touch);
        }
        $instance->fill($values);
        $instance->save(['touch' => false]);
        return $instance;
    }
    public function create(array $attributes, array $joining = [], $touch = true)
    {
        $instance = $this->related->newInstance($attributes);
        $instance->save(['touch' => false]);
        $this->attach($instance->getKey(), $joining, $touch);
        return $instance;
    }
    public function createMany(array $records, array $joinings = [])
    {
        $instances = [];
        foreach ($records as $key => $record) {
            $instances[] = $this->create($record, (array) Arr::get($joinings, $key), false);
        }
        $this->touchIfTouching();
        return $instances;
    }
    public function toggle($ids, $touch = true)
    {
        $changes = ['attached' => [], 'detached' => []];
        if ($ids instanceof Model) {
            $ids = $ids->getKey();
        }
        if ($ids instanceof Collection) {
            $ids = $ids->modelKeys();
        }
        $current = $this->newPivotQuery()->pluck($this->otherKey)->all();
        $records = $this->formatRecordsList((array) $ids);
        $detach = array_values(array_intersect($current, array_keys($records)));
        if (count($detach) > 0) {
            $this->detach($detach, false);
            $changes['detached'] = $this->castKeys($detach);
        }
        $attach = array_diff_key($records, array_flip($detach));
        if (count($attach) > 0) {
            $this->attach($attach, [], false);
            $changes['attached'] = array_keys($attach);
        }
        if ($touch && (count($changes['attached']) || count($changes['detached']))) {
            $this->touchIfTouching();
        }
        return $changes;
    }
    public function syncWithoutDetaching($ids)
    {
        return $this->sync($ids, false);
    }
    public function sync($ids, $detaching = true)
    {
        $changes = ['attached' => [], 'detached' => [], 'updated' => []];
        if ($ids instanceof Collection) {
            $ids = $ids->modelKeys();
        }
        $current = $this->newPivotQuery()->pluck($this->otherKey)->all();
        $records = $this->formatRecordsList($ids);
        $detach = array_diff($current, array_keys($records));
        if ($detaching && count($detach) > 0) {
            $this->detach($detach);
            $changes['detached'] = $this->castKeys($detach);
        }
        $changes = array_merge($changes, $this->attachNew($records, $current, false));
        if (count($changes['attached']) || count($changes['updated'])) {
            $this->touchIfTouching();
        }
        return $changes;
    }
    protected function formatRecordsList(array $records)
    {
        $results = [];
        foreach ($records as $id => $attributes) {
            if (!is_array($attributes)) {
                list($id, $attributes) = [$attributes, []];
            }
            $results[$id] = $attributes;
        }
        return $results;
    }
    protected function attachNew(array $records, array $current, $touch = true)
    {
        $changes = ['attached' => [], 'updated' => []];
        foreach ($records as $id => $attributes) {
            if (!in_array($id, $current)) {
                $this->attach($id, $attributes, $touch);
                $changes['attached'][] = is_numeric($id) ? (int) $id : (string) $id;
            } elseif (count($attributes) > 0 && $this->updateExistingPivot($id, $attributes, $touch)) {
                $changes['updated'][] = is_numeric($id) ? (int) $id : (string) $id;
            }
        }
        return $changes;
    }
    protected function castKeys(array $keys)
    {
        return (array) array_map(function ($v) {
            return is_numeric($v) ? (int) $v : (string) $v;
        }, $keys);
    }
    public function updateExistingPivot($id, array $attributes, $touch = true)
    {
        if (in_array($this->updatedAt(), $this->pivotColumns)) {
            $attributes = $this->setTimestampsOnAttach($attributes, true);
        }
        $updated = $this->newPivotStatementForId($id)->update($attributes);
        if ($touch) {
            $this->touchIfTouching();
        }
        return $updated;
    }
    public function attach($id, array $attributes = [], $touch = true)
    {
        if ($id instanceof Model) {
            $id = $id->getKey();
        }
        if ($id instanceof Collection) {
            $id = $id->modelKeys();
        }
        $query = $this->newPivotStatement();
        $query->insert($this->createAttachRecords((array) $id, $attributes));
        if ($touch) {
            $this->touchIfTouching();
        }
    }
    protected function createAttachRecords($ids, array $attributes)
    {
        $records = [];
        $timed = $this->hasPivotColumn($this->createdAt()) || $this->hasPivotColumn($this->updatedAt());
        foreach ($ids as $key => $value) {
            $records[] = $this->attacher($key, $value, $attributes, $timed);
        }
        return $records;
    }
    protected function attacher($key, $value, $attributes, $timed)
    {
        list($id, $extra) = $this->getAttachId($key, $value, $attributes);
        $record = $this->createAttachRecord($id, $timed);
        return array_merge($record, $extra);
    }
    protected function getAttachId($key, $value, array $attributes)
    {
        if (is_array($value)) {
            return [$key, array_merge($value, $attributes)];
        }
        return [$value, $attributes];
    }
    protected function createAttachRecord($id, $timed)
    {
        $record[$this->foreignKey] = $this->parent->getKey();
        $record[$this->otherKey] = $id;
        if ($timed) {
            $record = $this->setTimestampsOnAttach($record);
        }
        return $record;
    }
    protected function setTimestampsOnAttach(array $record, $exists = false)
    {
        $fresh = $this->parent->freshTimestamp();
        if (!$exists && $this->hasPivotColumn($this->createdAt())) {
            $record[$this->createdAt()] = $fresh;
        }
        if ($this->hasPivotColumn($this->updatedAt())) {
            $record[$this->updatedAt()] = $fresh;
        }
        return $record;
    }
    public function detach($ids = [], $touch = true)
    {
        if ($ids instanceof Model) {
            $ids = $ids->getKey();
        }
        if ($ids instanceof Collection) {
            $ids = $ids->modelKeys();
        }
        $query = $this->newPivotQuery();
        $ids = (array) $ids;
        if (count($ids) > 0) {
            $query->whereIn($this->otherKey, $ids);
        }
        $results = $query->delete();
        if ($touch) {
            $this->touchIfTouching();
        }
        return $results;
    }
    public function touchIfTouching()
    {
        if ($this->touchingParent()) {
            $this->getParent()->touch();
        }
        if ($this->getParent()->touches($this->relationName)) {
            $this->touch();
        }
    }
    protected function touchingParent()
    {
        return $this->getRelated()->touches($this->guessInverseRelation());
    }
    protected function guessInverseRelation()
    {
        return Str::camel(Str::plural(class_basename($this->getParent())));
    }
    protected function newPivotQuery()
    {
        $query = $this->newPivotStatement();
        foreach ($this->pivotWheres as $whereArgs) {
            call_user_func_array([$query, 'where'], $whereArgs);
        }
        foreach ($this->pivotWhereIns as $whereArgs) {
            call_user_func_array([$query, 'whereIn'], $whereArgs);
        }
        return $query->where($this->foreignKey, $this->parent->getKey());
    }
    public function newPivotStatement()
    {
        return $this->query->getQuery()->newQuery()->from($this->table);
    }
    public function newPivotStatementForId($id)
    {
        return $this->newPivotQuery()->where($this->otherKey, $id);
    }
    public function newPivot(array $attributes = [], $exists = false)
    {
        $pivot = $this->related->newPivot($this->parent, $attributes, $this->table, $exists);
        return $pivot->setPivotKeys($this->foreignKey, $this->otherKey);
    }
    public function newExistingPivot(array $attributes = [])
    {
        return $this->newPivot($attributes, true);
    }
    public function withPivot($columns)
    {
        $columns = is_array($columns) ? $columns : func_get_args();
        $this->pivotColumns = array_merge($this->pivotColumns, $columns);
        return $this;
    }
    public function withTimestamps($createdAt = null, $updatedAt = null)
    {
        $this->pivotCreatedAt = $createdAt;
        $this->pivotUpdatedAt = $updatedAt;
        return $this->withPivot($this->createdAt(), $this->updatedAt());
    }
    public function createdAt()
    {
        return $this->pivotCreatedAt ?: $this->parent->getCreatedAtColumn();
    }
    public function updatedAt()
    {
        return $this->pivotUpdatedAt ?: $this->parent->getUpdatedAtColumn();
    }
    public function getRelatedFreshUpdate()
    {
        return [$this->related->getUpdatedAtColumn() => $this->related->freshTimestampString()];
    }
    public function getHasCompareKey()
    {
        return $this->getForeignKey();
    }
    public function getForeignKey()
    {
        return $this->table . '.' . $this->foreignKey;
    }
    public function getOtherKey()
    {
        return $this->table . '.' . $this->otherKey;
    }
    public function getTable()
    {
        return $this->table;
    }
    public function getRelationName()
    {
        return $this->relationName;
    }
}
}

namespace Illuminate\Database\Eloquent {
class SoftDeletingScope implements Scope
{
    protected $extensions = ['ForceDelete', 'Restore', 'WithTrashed', 'WithoutTrashed', 'OnlyTrashed'];
    public function apply(Builder $builder, Model $model)
    {
        $builder->whereNull($model->getQualifiedDeletedAtColumn());
    }
    public function extend(Builder $builder)
    {
        foreach ($this->extensions as $extension) {
            $this->{"add{$extension}"}($builder);
        }
        $builder->onDelete(function (Builder $builder) {
            $column = $this->getDeletedAtColumn($builder);
            return $builder->update([$column => $builder->getModel()->freshTimestampString()]);
        });
    }
    protected function getDeletedAtColumn(Builder $builder)
    {
        if (count($builder->getQuery()->joins) > 0) {
            return $builder->getModel()->getQualifiedDeletedAtColumn();
        } else {
            return $builder->getModel()->getDeletedAtColumn();
        }
    }
    protected function addForceDelete(Builder $builder)
    {
        $builder->macro('forceDelete', function (Builder $builder) {
            return $builder->getQuery()->delete();
        });
    }
    protected function addRestore(Builder $builder)
    {
        $builder->macro('restore', function (Builder $builder) {
            $builder->withTrashed();
            return $builder->update([$builder->getModel()->getDeletedAtColumn() => null]);
        });
    }
    protected function addWithTrashed(Builder $builder)
    {
        $builder->macro('withTrashed', function (Builder $builder) {
            return $builder->withoutGlobalScope($this);
        });
    }
    protected function addWithoutTrashed(Builder $builder)
    {
        $builder->macro('withoutTrashed', function (Builder $builder) {
            $model = $builder->getModel();
            $builder->withoutGlobalScope($this)->whereNull($model->getQualifiedDeletedAtColumn());
            return $builder;
        });
    }
    protected function addOnlyTrashed(Builder $builder)
    {
        $builder->macro('onlyTrashed', function (Builder $builder) {
            $model = $builder->getModel();
            $builder->withoutGlobalScope($this)->whereNotNull($model->getQualifiedDeletedAtColumn());
            return $builder;
        });
    }
}
}

namespace Illuminate\Database\Eloquent {
use RuntimeException;
class ModelNotFoundException extends RuntimeException
{
    protected $model;
    public function setModel($model)
    {
        $this->model = $model;
        $this->message = "No query results for model [{$model}].";
        return $this;
    }
    public function getModel()
    {
        return $this->model;
    }
}
}

namespace Illuminate\Database\Eloquent {
use ArrayAccess;
use Faker\Generator as Faker;
use Symfony\Component\Finder\Finder;
class Factory implements ArrayAccess
{
    protected $faker;
    public function __construct(Faker $faker)
    {
        $this->faker = $faker;
    }
    protected $definitions = [];
    public static function construct(Faker $faker, $pathToFactories = null)
    {
        $pathToFactories = $pathToFactories ?: database_path('factories');
        return (new static($faker))->load($pathToFactories);
    }
    public function defineAs($class, $name, callable $attributes)
    {
        return $this->define($class, $attributes, $name);
    }
    public function define($class, callable $attributes, $name = 'default')
    {
        $this->definitions[$class][$name] = $attributes;
    }
    public function create($class, array $attributes = [])
    {
        return $this->of($class)->create($attributes);
    }
    public function createAs($class, $name, array $attributes = [])
    {
        return $this->of($class, $name)->create($attributes);
    }
    public function load($path)
    {
        $factory = $this;
        if (is_dir($path)) {
            foreach (Finder::create()->files()->in($path) as $file) {
                require $file->getRealPath();
            }
        }
        return $factory;
    }
    public function make($class, array $attributes = [])
    {
        return $this->of($class)->make($attributes);
    }
    public function makeAs($class, $name, array $attributes = [])
    {
        return $this->of($class, $name)->make($attributes);
    }
    public function rawOf($class, $name, array $attributes = [])
    {
        return $this->raw($class, $attributes, $name);
    }
    public function raw($class, array $attributes = [], $name = 'default')
    {
        $raw = call_user_func($this->definitions[$class][$name], $this->faker);
        return array_merge($raw, $attributes);
    }
    public function of($class, $name = 'default')
    {
        return new FactoryBuilder($class, $name, $this->definitions, $this->faker);
    }
    public function offsetExists($offset)
    {
        return isset($this->definitions[$offset]);
    }
    public function offsetGet($offset)
    {
        return $this->make($offset);
    }
    public function offsetSet($offset, $value)
    {
        return $this->define($offset, $value);
    }
    public function offsetUnset($offset)
    {
        unset($this->definitions[$offset]);
    }
}
}

namespace Illuminate\Database\Eloquent {
use Illuminate\Contracts\Queue\EntityNotFoundException;
use Illuminate\Contracts\Queue\EntityResolver as EntityResolverContract;
class QueueEntityResolver implements EntityResolverContract
{
    public function resolve($type, $id)
    {
        $instance = (new $type())->find($id);
        if ($instance) {
            return $instance;
        }
        throw new EntityNotFoundException($type, $id);
    }
}
}

namespace Illuminate\Database\Eloquent {
trait SoftDeletes
{
    protected $forceDeleting = false;
    public static function bootSoftDeletes()
    {
        static::addGlobalScope(new SoftDeletingScope());
    }
    public function forceDelete()
    {
        $this->forceDeleting = true;
        $deleted = $this->delete();
        $this->forceDeleting = false;
        return $deleted;
    }
    protected function performDeleteOnModel()
    {
        if ($this->forceDeleting) {
            return $this->newQueryWithoutScopes()->where($this->getKeyName(), $this->getKey())->forceDelete();
        }
        return $this->runSoftDelete();
    }
    protected function runSoftDelete()
    {
        $query = $this->newQueryWithoutScopes()->where($this->getKeyName(), $this->getKey());
        $this->{$this->getDeletedAtColumn()} = $time = $this->freshTimestamp();
        $query->update([$this->getDeletedAtColumn() => $this->fromDateTime($time)]);
    }
    public function restore()
    {
        if ($this->fireModelEvent('restoring') === false) {
            return false;
        }
        $this->{$this->getDeletedAtColumn()} = null;
        $this->exists = true;
        $result = $this->save();
        $this->fireModelEvent('restored', false);
        return $result;
    }
    public function trashed()
    {
        return !is_null($this->{$this->getDeletedAtColumn()});
    }
    public static function restoring($callback)
    {
        static::registerModelEvent('restoring', $callback);
    }
    public static function restored($callback)
    {
        static::registerModelEvent('restored', $callback);
    }
    public function isForceDeleting()
    {
        return $this->forceDeleting;
    }
    public function getDeletedAtColumn()
    {
        return defined('static::DELETED_AT') ? static::DELETED_AT : 'deleted_at';
    }
    public function getQualifiedDeletedAtColumn()
    {
        return $this->getTable() . '.' . $this->getDeletedAtColumn();
    }
}
}

namespace Illuminate\Database\Eloquent {
use RuntimeException;
class MassAssignmentException extends RuntimeException
{
}
}

namespace Illuminate\Database\Eloquent {
interface Scope
{
    public function apply(Builder $builder, Model $model);
}
}

namespace Illuminate\Database\Eloquent {
use LogicException;
use Illuminate\Support\Arr;
use Illuminate\Contracts\Queue\QueueableCollection;
use Illuminate\Support\Collection as BaseCollection;
class Collection extends BaseCollection implements QueueableCollection
{
    public function find($key, $default = null)
    {
        if ($key instanceof Model) {
            $key = $key->getKey();
        }
        return Arr::first($this->items, function ($model) use($key) {
            return $model->getKey() == $key;
        }, $default);
    }
    public function load($relations)
    {
        if (count($this->items) > 0) {
            if (is_string($relations)) {
                $relations = func_get_args();
            }
            $query = $this->first()->newQuery()->with($relations);
            $this->items = $query->eagerLoadRelations($this->items);
        }
        return $this;
    }
    public function add($item)
    {
        $this->items[] = $item;
        return $this;
    }
    public function contains($key, $value = null)
    {
        if (func_num_args() == 2) {
            return parent::contains($key, $value);
        }
        if ($this->useAsCallable($key)) {
            return parent::contains($key);
        }
        $key = $key instanceof Model ? $key->getKey() : $key;
        return parent::contains(function ($model) use($key) {
            return $model->getKey() == $key;
        });
    }
    public function modelKeys()
    {
        return array_map(function ($model) {
            return $model->getKey();
        }, $this->items);
    }
    public function merge($items)
    {
        $dictionary = $this->getDictionary();
        foreach ($items as $item) {
            $dictionary[$item->getKey()] = $item;
        }
        return new static(array_values($dictionary));
    }
    public function map(callable $callback)
    {
        $result = parent::map($callback);
        return $result->contains(function ($item) {
            return !$item instanceof Model;
        }) ? $result->toBase() : $result;
    }
    public function diff($items)
    {
        $diff = new static();
        $dictionary = $this->getDictionary($items);
        foreach ($this->items as $item) {
            if (!isset($dictionary[$item->getKey()])) {
                $diff->add($item);
            }
        }
        return $diff;
    }
    public function intersect($items)
    {
        $intersect = new static();
        $dictionary = $this->getDictionary($items);
        foreach ($this->items as $item) {
            if (isset($dictionary[$item->getKey()])) {
                $intersect->add($item);
            }
        }
        return $intersect;
    }
    public function unique($key = null, $strict = false)
    {
        if (!is_null($key)) {
            return parent::unique($key, $strict);
        }
        return new static(array_values($this->getDictionary()));
    }
    public function only($keys)
    {
        $dictionary = Arr::only($this->getDictionary(), $keys);
        return new static(array_values($dictionary));
    }
    public function except($keys)
    {
        $dictionary = Arr::except($this->getDictionary(), $keys);
        return new static(array_values($dictionary));
    }
    public function makeHidden($attributes)
    {
        return $this->each(function ($model) use($attributes) {
            $model->addHidden($attributes);
        });
    }
    public function makeVisible($attributes)
    {
        return $this->each(function ($model) use($attributes) {
            $model->makeVisible($attributes);
        });
    }
    public function getDictionary($items = null)
    {
        $items = is_null($items) ? $this->items : $items;
        $dictionary = [];
        foreach ($items as $value) {
            $dictionary[$value->getKey()] = $value;
        }
        return $dictionary;
    }
    public function pluck($value, $key = null)
    {
        return $this->toBase()->pluck($value, $key);
    }
    public function keys()
    {
        return $this->toBase()->keys();
    }
    public function zip($items)
    {
        return call_user_func_array([$this->toBase(), 'zip'], func_get_args());
    }
    public function collapse()
    {
        return $this->toBase()->collapse();
    }
    public function flatten($depth = INF)
    {
        return $this->toBase()->flatten($depth);
    }
    public function flip()
    {
        return $this->toBase()->flip();
    }
    public function getQueueableClass()
    {
        if ($this->count() === 0) {
            return;
        }
        $class = get_class($this->first());
        $this->each(function ($model) use($class) {
            if (get_class($model) !== $class) {
                throw new LogicException('Queueing collections with multiple model types is not supported.');
            }
        });
        return $class;
    }
    public function getQueueableIds()
    {
        return $this->modelKeys();
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\Command;
class BaseCommand extends Command
{
    protected function getMigrationPath()
    {
        return $this->laravel->databasePath() . DIRECTORY_SEPARATOR . 'migrations';
    }
    protected function getMigrationPaths()
    {
        if ($this->input->hasOption('path') && $this->option('path')) {
            return [$this->laravel->basePath() . '/' . $this->option('path')];
        }
        return array_merge([$this->getMigrationPath()], $this->migrator->paths());
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\Command;
use Illuminate\Console\ConfirmableTrait;
use Symfony\Component\Console\Input\InputOption;
class RefreshCommand extends Command
{
    use ConfirmableTrait;
    protected $name = 'migrate:refresh';
    protected $description = 'Reset and re-run all migrations';
    public function fire()
    {
        if (!$this->confirmToProceed()) {
            return;
        }
        $database = $this->input->getOption('database');
        $force = $this->input->getOption('force');
        $path = $this->input->getOption('path');
        $step = $this->input->getOption('step') ?: 0;
        if ($step > 0) {
            $this->call('migrate:rollback', ['--database' => $database, '--force' => $force, '--path' => $path, '--step' => $step]);
        } else {
            $this->call('migrate:reset', ['--database' => $database, '--force' => $force, '--path' => $path]);
        }
        $this->call('migrate', ['--database' => $database, '--force' => $force, '--path' => $path]);
        if ($this->needsSeeding()) {
            $this->runSeeder($database);
        }
    }
    protected function needsSeeding()
    {
        return $this->option('seed') || $this->option('seeder');
    }
    protected function runSeeder($database)
    {
        $class = $this->option('seeder') ?: 'DatabaseSeeder';
        $force = $this->input->getOption('force');
        $this->call('db:seed', ['--database' => $database, '--class' => $class, '--force' => $force]);
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use.'], ['force', null, InputOption::VALUE_NONE, 'Force the operation to run when in production.'], ['path', null, InputOption::VALUE_OPTIONAL, 'The path of migrations files to be executed.'], ['seed', null, InputOption::VALUE_NONE, 'Indicates if the seed task should be re-run.'], ['seeder', null, InputOption::VALUE_OPTIONAL, 'The class name of the root seeder.'], ['step', null, InputOption::VALUE_OPTIONAL, 'The number of migrations to be reverted & re-run.']];
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\ConfirmableTrait;
use Illuminate\Database\Migrations\Migrator;
use Symfony\Component\Console\Input\InputOption;
class MigrateCommand extends BaseCommand
{
    use ConfirmableTrait;
    protected $name = 'migrate';
    protected $description = 'Run the database migrations';
    protected $migrator;
    public function __construct(Migrator $migrator)
    {
        parent::__construct();
        $this->migrator = $migrator;
    }
    public function fire()
    {
        if (!$this->confirmToProceed()) {
            return;
        }
        $this->prepareDatabase();
        $this->migrator->run($this->getMigrationPaths(), ['pretend' => $this->option('pretend'), 'step' => $this->option('step')]);
        foreach ($this->migrator->getNotes() as $note) {
            $this->output->writeln($note);
        }
        if ($this->option('seed')) {
            $this->call('db:seed', ['--force' => true]);
        }
    }
    protected function prepareDatabase()
    {
        $this->migrator->setConnection($this->option('database'));
        if (!$this->migrator->repositoryExists()) {
            $options = ['--database' => $this->option('database')];
            $this->call('migrate:install', $options);
        }
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use.'], ['force', null, InputOption::VALUE_NONE, 'Force the operation to run when in production.'], ['path', null, InputOption::VALUE_OPTIONAL, 'The path of migrations files to be executed.'], ['pretend', null, InputOption::VALUE_NONE, 'Dump the SQL queries that would be run.'], ['seed', null, InputOption::VALUE_NONE, 'Indicates if the seed task should be re-run.'], ['step', null, InputOption::VALUE_NONE, 'Force the migrations to be run so they can be rolled back individually.']];
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\ConfirmableTrait;
use Illuminate\Database\Migrations\Migrator;
use Symfony\Component\Console\Input\InputOption;
class RollbackCommand extends BaseCommand
{
    use ConfirmableTrait;
    protected $name = 'migrate:rollback';
    protected $description = 'Rollback the last database migration';
    protected $migrator;
    public function __construct(Migrator $migrator)
    {
        parent::__construct();
        $this->migrator = $migrator;
    }
    public function fire()
    {
        if (!$this->confirmToProceed()) {
            return;
        }
        $this->migrator->setConnection($this->option('database'));
        $this->migrator->rollback($this->getMigrationPaths(), ['pretend' => $this->option('pretend'), 'step' => (int) $this->option('step')]);
        foreach ($this->migrator->getNotes() as $note) {
            $this->output->writeln($note);
        }
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use.'], ['force', null, InputOption::VALUE_NONE, 'Force the operation to run when in production.'], ['path', null, InputOption::VALUE_OPTIONAL, 'The path of migrations files to be executed.'], ['pretend', null, InputOption::VALUE_NONE, 'Dump the SQL queries that would be run.'], ['step', null, InputOption::VALUE_OPTIONAL, 'The number of migrations to be reverted.']];
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Support\Collection;
use Illuminate\Database\Migrations\Migrator;
use Symfony\Component\Console\Input\InputOption;
class StatusCommand extends BaseCommand
{
    protected $name = 'migrate:status';
    protected $description = 'Show the status of each migration';
    protected $migrator;
    public function __construct(Migrator $migrator)
    {
        parent::__construct();
        $this->migrator = $migrator;
    }
    public function fire()
    {
        if (!$this->migrator->repositoryExists()) {
            return $this->error('No migrations found.');
        }
        $this->migrator->setConnection($this->option('database'));
        $ran = $this->migrator->getRepository()->getRan();
        $migrations = Collection::make($this->getAllMigrationFiles())->map(function ($migration) use($ran) {
            return in_array($this->migrator->getMigrationName($migration), $ran) ? ['<info>Y</info>', $this->migrator->getMigrationName($migration)] : ['<fg=red>N</fg=red>', $this->migrator->getMigrationName($migration)];
        });
        if (count($migrations) > 0) {
            $this->table(['Ran?', 'Migration'], $migrations);
        } else {
            $this->error('No migrations found');
        }
    }
    protected function getAllMigrationFiles()
    {
        return $this->migrator->getMigrationFiles($this->getMigrationPaths());
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use.'], ['path', null, InputOption::VALUE_OPTIONAL, 'The path of migrations files to use.']];
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Support\Composer;
use Illuminate\Database\Migrations\MigrationCreator;
class MigrateMakeCommand extends BaseCommand
{
    protected $signature = 'make:migration {name : The name of the migration.}
        {--create= : The table to be created.}
        {--table= : The table to migrate.}
        {--path= : The location where the migration file should be created.}';
    protected $description = 'Create a new migration file';
    protected $creator;
    protected $composer;
    public function __construct(MigrationCreator $creator, Composer $composer)
    {
        parent::__construct();
        $this->creator = $creator;
        $this->composer = $composer;
    }
    public function fire()
    {
        $name = trim($this->input->getArgument('name'));
        $table = $this->input->getOption('table');
        $create = $this->input->getOption('create') ?: false;
        if (!$table && is_string($create)) {
            $table = $create;
            $create = true;
        }
        $this->writeMigration($name, $table, $create);
        $this->composer->dumpAutoloads();
    }
    protected function writeMigration($name, $table, $create)
    {
        $path = $this->getMigrationPath();
        $file = pathinfo($this->creator->create($name, $path, $table, $create), PATHINFO_FILENAME);
        $this->line("<info>Created Migration:</info> {$file}");
    }
    protected function getMigrationPath()
    {
        if (!is_null($targetPath = $this->input->getOption('path'))) {
            return $this->laravel->basePath() . '/' . $targetPath;
        }
        return parent::getMigrationPath();
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\ConfirmableTrait;
use Illuminate\Database\Migrations\Migrator;
use Symfony\Component\Console\Input\InputOption;
class ResetCommand extends BaseCommand
{
    use ConfirmableTrait;
    protected $name = 'migrate:reset';
    protected $description = 'Rollback all database migrations';
    protected $migrator;
    public function __construct(Migrator $migrator)
    {
        parent::__construct();
        $this->migrator = $migrator;
    }
    public function fire()
    {
        if (!$this->confirmToProceed()) {
            return;
        }
        $this->migrator->setConnection($this->option('database'));
        if (!$this->migrator->repositoryExists()) {
            return $this->comment('Migration table not found.');
        }
        $this->migrator->reset($this->getMigrationPaths(), $this->option('pretend'));
        foreach ($this->migrator->getNotes() as $note) {
            $this->output->writeln($note);
        }
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use.'], ['force', null, InputOption::VALUE_NONE, 'Force the operation to run when in production.'], ['path', null, InputOption::VALUE_OPTIONAL, 'The path of migrations files to be executed.'], ['pretend', null, InputOption::VALUE_NONE, 'Dump the SQL queries that would be run.']];
    }
}
}

namespace Illuminate\Database\Console\Migrations {
use Illuminate\Console\Command;
use Symfony\Component\Console\Input\InputOption;
use Illuminate\Database\Migrations\MigrationRepositoryInterface;
class InstallCommand extends Command
{
    protected $name = 'migrate:install';
    protected $description = 'Create the migration repository';
    protected $repository;
    public function __construct(MigrationRepositoryInterface $repository)
    {
        parent::__construct();
        $this->repository = $repository;
    }
    public function fire()
    {
        $this->repository->setSource($this->input->getOption('database'));
        $this->repository->createRepository();
        $this->info('Migration table created successfully.');
    }
    protected function getOptions()
    {
        return [['database', null, InputOption::VALUE_OPTIONAL, 'The database connection to use.']];
    }
}
}

namespace Illuminate\Database {
use Exception;
use Illuminate\Support\Str;
trait DetectsLostConnections
{
    protected function causedByLostConnection(Exception $e)
    {
        $message = $e->getMessage();
        return Str::contains($message, ['server has gone away', 'no connection to the server', 'Lost connection', 'is dead or not enabled', 'Error while sending', 'decryption failed or bad record mac', 'server closed the connection unexpectedly', 'SSL connection has been closed unexpectedly', 'Error writing data to the connection', 'Resource deadlock avoided']);
    }
}
}

namespace Illuminate\Database {
use Illuminate\Support\ServiceProvider;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Database\Migrations\MigrationCreator;
use Illuminate\Database\Console\Migrations\ResetCommand;
use Illuminate\Database\Console\Migrations\StatusCommand;
use Illuminate\Database\Console\Migrations\InstallCommand;
use Illuminate\Database\Console\Migrations\MigrateCommand;
use Illuminate\Database\Console\Migrations\RefreshCommand;
use Illuminate\Database\Console\Migrations\RollbackCommand;
use Illuminate\Database\Console\Migrations\MigrateMakeCommand;
use Illuminate\Database\Migrations\DatabaseMigrationRepository;
class MigrationServiceProvider extends ServiceProvider
{
    protected $defer = true;
    public function register()
    {
        $this->registerRepository();
        $this->registerMigrator();
        $this->registerCreator();
        $this->registerCommands();
    }
    protected function registerRepository()
    {
        $this->app->singleton('migration.repository', function ($app) {
            $table = $app['config']['database.migrations'];
            return new DatabaseMigrationRepository($app['db'], $table);
        });
    }
    protected function registerMigrator()
    {
        $this->app->singleton('migrator', function ($app) {
            $repository = $app['migration.repository'];
            return new Migrator($repository, $app['db'], $app['files']);
        });
    }
    protected function registerCreator()
    {
        $this->app->singleton('migration.creator', function ($app) {
            return new MigrationCreator($app['files']);
        });
    }
    protected function registerCommands()
    {
        $commands = ['Migrate', 'Rollback', 'Reset', 'Refresh', 'Install', 'Make', 'Status'];
        foreach ($commands as $command) {
            $this->{'register' . $command . 'Command'}();
        }
        $this->commands('command.migrate', 'command.migrate.make', 'command.migrate.install', 'command.migrate.rollback', 'command.migrate.reset', 'command.migrate.refresh', 'command.migrate.status');
    }
    protected function registerMigrateCommand()
    {
        $this->app->singleton('command.migrate', function ($app) {
            return new MigrateCommand($app['migrator']);
        });
    }
    protected function registerRollbackCommand()
    {
        $this->app->singleton('command.migrate.rollback', function ($app) {
            return new RollbackCommand($app['migrator']);
        });
    }
    protected function registerResetCommand()
    {
        $this->app->singleton('command.migrate.reset', function ($app) {
            return new ResetCommand($app['migrator']);
        });
    }
    protected function registerRefreshCommand()
    {
        $this->app->singleton('command.migrate.refresh', function () {
            return new RefreshCommand();
        });
    }
    protected function registerMakeCommand()
    {
        $this->app->singleton('command.migrate.make', function ($app) {
            $creator = $app['migration.creator'];
            $composer = $app['composer'];
            return new MigrateMakeCommand($creator, $composer);
        });
    }
    protected function registerStatusCommand()
    {
        $this->app->singleton('command.migrate.status', function ($app) {
            return new StatusCommand($app['migrator']);
        });
    }
    protected function registerInstallCommand()
    {
        $this->app->singleton('command.migrate.install', function ($app) {
            return new InstallCommand($app['migration.repository']);
        });
    }
    public function provides()
    {
        return ['migrator', 'migration.repository', 'command.migrate', 'command.migrate.rollback', 'command.migrate.reset', 'command.migrate.refresh', 'command.migrate.install', 'command.migrate.status', 'migration.creator', 'command.migrate.make'];
    }
}
}

namespace Illuminate\Database {
use PDOException;
use Illuminate\Support\Str;
class QueryException extends PDOException
{
    protected $sql;
    protected $bindings;
    public function __construct($sql, array $bindings, $previous)
    {
        parent::__construct('', 0, $previous);
        $this->sql = $sql;
        $this->bindings = $bindings;
        $this->previous = $previous;
        $this->code = $previous->getCode();
        $this->message = $this->formatMessage($sql, $bindings, $previous);
        if ($previous instanceof PDOException) {
            $this->errorInfo = $previous->errorInfo;
        }
    }
    protected function formatMessage($sql, $bindings, $previous)
    {
        return $previous->getMessage() . ' (SQL: ' . Str::replaceArray('?', $bindings, $sql) . ')';
    }
    public function getSql()
    {
        return $this->sql;
    }
    public function getBindings()
    {
        return $this->bindings;
    }
}
}

namespace Illuminate\Database {
class ConnectionResolver implements ConnectionResolverInterface
{
    protected $connections = [];
    protected $default;
    public function __construct(array $connections = [])
    {
        foreach ($connections as $name => $connection) {
            $this->addConnection($name, $connection);
        }
    }
    public function connection($name = null)
    {
        if (is_null($name)) {
            $name = $this->getDefaultConnection();
        }
        return $this->connections[$name];
    }
    public function addConnection($name, ConnectionInterface $connection)
    {
        $this->connections[$name] = $connection;
    }
    public function hasConnection($name)
    {
        return isset($this->connections[$name]);
    }
    public function getDefaultConnection()
    {
        return $this->default;
    }
    public function setDefaultConnection($name)
    {
        $this->default = $name;
    }
}
}

namespace Illuminate\Encryption {
use RuntimeException;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
class Encrypter implements EncrypterContract
{
    protected $key;
    protected $cipher;
    public function __construct($key, $cipher = 'AES-128-CBC')
    {
        $key = (string) $key;
        if (static::supported($key, $cipher)) {
            $this->key = $key;
            $this->cipher = $cipher;
        } else {
            throw new RuntimeException('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');
        }
    }
    public static function supported($key, $cipher)
    {
        $length = mb_strlen($key, '8bit');
        return $cipher === 'AES-128-CBC' && $length === 16 || $cipher === 'AES-256-CBC' && $length === 32;
    }
    public function encrypt($value)
    {
        $iv = random_bytes(16);
        $value = \openssl_encrypt(serialize($value), $this->cipher, $this->key, 0, $iv);
        if ($value === false) {
            throw new EncryptException('Could not encrypt the data.');
        }
        $mac = $this->hash($iv = base64_encode($iv), $value);
        $json = json_encode(compact('iv', 'value', 'mac'));
        if (!is_string($json)) {
            throw new EncryptException('Could not encrypt the data.');
        }
        return base64_encode($json);
    }
    public function decrypt($payload)
    {
        $payload = $this->getJsonPayload($payload);
        $iv = base64_decode($payload['iv']);
        $decrypted = \openssl_decrypt($payload['value'], $this->cipher, $this->key, 0, $iv);
        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }
        return unserialize($decrypted);
    }
    protected function hash($iv, $value)
    {
        return hash_hmac('sha256', $iv . $value, $this->key);
    }
    protected function getJsonPayload($payload)
    {
        $payload = json_decode(base64_decode($payload), true);
        if (!$this->validPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }
        if (!$this->validMac($payload)) {
            throw new DecryptException('The MAC is invalid.');
        }
        return $payload;
    }
    protected function validPayload($payload)
    {
        return is_array($payload) && isset($payload['iv'], $payload['value'], $payload['mac']);
    }
    protected function validMac(array $payload)
    {
        $bytes = random_bytes(16);
        $calcMac = hash_hmac('sha256', $this->hash($payload['iv'], $payload['value']), $bytes, true);
        return hash_equals(hash_hmac('sha256', $payload['mac'], $bytes, true), $calcMac);
    }
    public function getKey()
    {
        return $this->key;
    }
}
}

namespace Illuminate\Encryption {
use Illuminate\Support\Str;
use Illuminate\Support\ServiceProvider;
class EncryptionServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton('encrypter', function ($app) {
            $config = $app->make('config')->get('app');
            if (Str::startsWith($key = $config['key'], 'base64:')) {
                $key = base64_decode(substr($key, 7));
            }
            return new Encrypter($key, $config['cipher']);
        });
    }
}
}

namespace Psr\Log {
interface LoggerInterface
{
    public function emergency($message, array $context = array());
    public function alert($message, array $context = array());
    public function critical($message, array $context = array());
    public function error($message, array $context = array());
    public function warning($message, array $context = array());
    public function notice($message, array $context = array());
    public function info($message, array $context = array());
    public function debug($message, array $context = array());
    public function log($level, $message, array $context = array());
}
}

namespace Monolog {
use Monolog\Handler\HandlerInterface;
use Monolog\Handler\StreamHandler;
use Psr\Log\LoggerInterface;
use Psr\Log\InvalidArgumentException;
class Logger implements LoggerInterface
{
    const DEBUG = 100;
    const INFO = 200;
    const NOTICE = 250;
    const WARNING = 300;
    const ERROR = 400;
    const CRITICAL = 500;
    const ALERT = 550;
    const EMERGENCY = 600;
    const API = 1;
    protected static $levels = array(self::DEBUG => 'DEBUG', self::INFO => 'INFO', self::NOTICE => 'NOTICE', self::WARNING => 'WARNING', self::ERROR => 'ERROR', self::CRITICAL => 'CRITICAL', self::ALERT => 'ALERT', self::EMERGENCY => 'EMERGENCY');
    protected static $timezone;
    protected $name;
    protected $handlers;
    protected $processors;
    protected $microsecondTimestamps = true;
    public function __construct($name, array $handlers = array(), array $processors = array())
    {
        $this->name = $name;
        $this->handlers = $handlers;
        $this->processors = $processors;
    }
    public function getName()
    {
        return $this->name;
    }
    public function withName($name)
    {
        $new = clone $this;
        $new->name = $name;
        return $new;
    }
    public function pushHandler(HandlerInterface $handler)
    {
        array_unshift($this->handlers, $handler);
        return $this;
    }
    public function popHandler()
    {
        if (!$this->handlers) {
            throw new \LogicException('You tried to pop from an empty handler stack.');
        }
        return array_shift($this->handlers);
    }
    public function setHandlers(array $handlers)
    {
        $this->handlers = array();
        foreach (array_reverse($handlers) as $handler) {
            $this->pushHandler($handler);
        }
        return $this;
    }
    public function getHandlers()
    {
        return $this->handlers;
    }
    public function pushProcessor($callback)
    {
        if (!is_callable($callback)) {
            throw new \InvalidArgumentException('Processors must be valid callables (callback or object with an __invoke method), ' . var_export($callback, true) . ' given');
        }
        array_unshift($this->processors, $callback);
        return $this;
    }
    public function popProcessor()
    {
        if (!$this->processors) {
            throw new \LogicException('You tried to pop from an empty processor stack.');
        }
        return array_shift($this->processors);
    }
    public function getProcessors()
    {
        return $this->processors;
    }
    public function useMicrosecondTimestamps($micro)
    {
        $this->microsecondTimestamps = (bool) $micro;
    }
    public function addRecord($level, $message, array $context = array())
    {
        if (!$this->handlers) {
            $this->pushHandler(new StreamHandler('php://stderr', static::DEBUG));
        }
        $levelName = static::getLevelName($level);
        $handlerKey = null;
        reset($this->handlers);
        while ($handler = current($this->handlers)) {
            if ($handler->isHandling(array('level' => $level))) {
                $handlerKey = key($this->handlers);
                break;
            }
            next($this->handlers);
        }
        if (null === $handlerKey) {
            return false;
        }
        if (!static::$timezone) {
            static::$timezone = new \DateTimeZone(date_default_timezone_get() ?: 'UTC');
        }
        if ($this->microsecondTimestamps) {
            $ts = \DateTime::createFromFormat('U.u', sprintf('%.6F', microtime(true)), static::$timezone);
        } else {
            $ts = new \DateTime(null, static::$timezone);
        }
        $ts->setTimezone(static::$timezone);
        $record = array('message' => (string) $message, 'context' => $context, 'level' => $level, 'level_name' => $levelName, 'channel' => $this->name, 'datetime' => $ts, 'extra' => array());
        foreach ($this->processors as $processor) {
            $record = call_user_func($processor, $record);
        }
        while ($handler = current($this->handlers)) {
            if (true === $handler->handle($record)) {
                break;
            }
            next($this->handlers);
        }
        return true;
    }
    public function addDebug($message, array $context = array())
    {
        return $this->addRecord(static::DEBUG, $message, $context);
    }
    public function addInfo($message, array $context = array())
    {
        return $this->addRecord(static::INFO, $message, $context);
    }
    public function addNotice($message, array $context = array())
    {
        return $this->addRecord(static::NOTICE, $message, $context);
    }
    public function addWarning($message, array $context = array())
    {
        return $this->addRecord(static::WARNING, $message, $context);
    }
    public function addError($message, array $context = array())
    {
        return $this->addRecord(static::ERROR, $message, $context);
    }
    public function addCritical($message, array $context = array())
    {
        return $this->addRecord(static::CRITICAL, $message, $context);
    }
    public function addAlert($message, array $context = array())
    {
        return $this->addRecord(static::ALERT, $message, $context);
    }
    public function addEmergency($message, array $context = array())
    {
        return $this->addRecord(static::EMERGENCY, $message, $context);
    }
    public static function getLevels()
    {
        return array_flip(static::$levels);
    }
    public static function getLevelName($level)
    {
        if (!isset(static::$levels[$level])) {
            throw new InvalidArgumentException('Level "' . $level . '" is not defined, use one of: ' . implode(', ', array_keys(static::$levels)));
        }
        return static::$levels[$level];
    }
    public static function toMonologLevel($level)
    {
        if (is_string($level) && defined(__CLASS__ . '::' . strtoupper($level))) {
            return constant(__CLASS__ . '::' . strtoupper($level));
        }
        return $level;
    }
    public function isHandling($level)
    {
        $record = array('level' => $level);
        foreach ($this->handlers as $handler) {
            if ($handler->isHandling($record)) {
                return true;
            }
        }
        return false;
    }
    public function log($level, $message, array $context = array())
    {
        $level = static::toMonologLevel($level);
        return $this->addRecord($level, $message, $context);
    }
    public function debug($message, array $context = array())
    {
        return $this->addRecord(static::DEBUG, $message, $context);
    }
    public function info($message, array $context = array())
    {
        return $this->addRecord(static::INFO, $message, $context);
    }
    public function notice($message, array $context = array())
    {
        return $this->addRecord(static::NOTICE, $message, $context);
    }
    public function warn($message, array $context = array())
    {
        return $this->addRecord(static::WARNING, $message, $context);
    }
    public function warning($message, array $context = array())
    {
        return $this->addRecord(static::WARNING, $message, $context);
    }
    public function err($message, array $context = array())
    {
        return $this->addRecord(static::ERROR, $message, $context);
    }
    public function error($message, array $context = array())
    {
        return $this->addRecord(static::ERROR, $message, $context);
    }
    public function crit($message, array $context = array())
    {
        return $this->addRecord(static::CRITICAL, $message, $context);
    }
    public function critical($message, array $context = array())
    {
        return $this->addRecord(static::CRITICAL, $message, $context);
    }
    public function alert($message, array $context = array())
    {
        return $this->addRecord(static::ALERT, $message, $context);
    }
    public function emerg($message, array $context = array())
    {
        return $this->addRecord(static::EMERGENCY, $message, $context);
    }
    public function emergency($message, array $context = array())
    {
        return $this->addRecord(static::EMERGENCY, $message, $context);
    }
    public static function setTimezone(\DateTimeZone $tz)
    {
        self::$timezone = $tz;
    }
}
}

namespace Monolog\Handler {
use Monolog\Logger;
use Monolog\Formatter\FormatterInterface;
use Monolog\Formatter\LineFormatter;
abstract class AbstractHandler implements HandlerInterface
{
    protected $level = Logger::DEBUG;
    protected $bubble = true;
    protected $formatter;
    protected $processors = array();
    public function __construct($level = Logger::DEBUG, $bubble = true)
    {
        $this->setLevel($level);
        $this->bubble = $bubble;
    }
    public function isHandling(array $record)
    {
        return $record['level'] >= $this->level;
    }
    public function handleBatch(array $records)
    {
        foreach ($records as $record) {
            $this->handle($record);
        }
    }
    public function close()
    {
    }
    public function pushProcessor($callback)
    {
        if (!is_callable($callback)) {
            throw new \InvalidArgumentException('Processors must be valid callables (callback or object with an __invoke method), ' . var_export($callback, true) . ' given');
        }
        array_unshift($this->processors, $callback);
        return $this;
    }
    public function popProcessor()
    {
        if (!$this->processors) {
            throw new \LogicException('You tried to pop from an empty processor stack.');
        }
        return array_shift($this->processors);
    }
    public function setFormatter(FormatterInterface $formatter)
    {
        $this->formatter = $formatter;
        return $this;
    }
    public function getFormatter()
    {
        if (!$this->formatter) {
            $this->formatter = $this->getDefaultFormatter();
        }
        return $this->formatter;
    }
    public function setLevel($level)
    {
        $this->level = Logger::toMonologLevel($level);
        return $this;
    }
    public function getLevel()
    {
        return $this->level;
    }
    public function setBubble($bubble)
    {
        $this->bubble = $bubble;
        return $this;
    }
    public function getBubble()
    {
        return $this->bubble;
    }
    public function __destruct()
    {
        try {
            $this->close();
        } catch (\Exception $e) {
        } catch (\Throwable $e) {
        }
    }
    protected function getDefaultFormatter()
    {
        return new LineFormatter();
    }
}
}

namespace Monolog\Handler {
abstract class AbstractProcessingHandler extends AbstractHandler
{
    public function handle(array $record)
    {
        if (!$this->isHandling($record)) {
            return false;
        }
        $record = $this->processRecord($record);
        $record['formatted'] = $this->getFormatter()->format($record);
        $this->write($record);
        return false === $this->bubble;
    }
    protected abstract function write(array $record);
    protected function processRecord(array $record)
    {
        if ($this->processors) {
            foreach ($this->processors as $processor) {
                $record = call_user_func($processor, $record);
            }
        }
        return $record;
    }
}
}

namespace Monolog\Handler {
use Monolog\Logger;
class StreamHandler extends AbstractProcessingHandler
{
    protected $stream;
    protected $url;
    private $errorMessage;
    protected $filePermission;
    protected $useLocking;
    private $dirCreated;
    public function __construct($stream, $level = Logger::DEBUG, $bubble = true, $filePermission = null, $useLocking = false)
    {
        parent::__construct($level, $bubble);
        if (is_resource($stream)) {
            $this->stream = $stream;
        } elseif (is_string($stream)) {
            $this->url = $stream;
        } else {
            throw new \InvalidArgumentException('A stream must either be a resource or a string.');
        }
        $this->filePermission = $filePermission;
        $this->useLocking = $useLocking;
    }
    public function close()
    {
        if ($this->url && is_resource($this->stream)) {
            fclose($this->stream);
        }
        $this->stream = null;
    }
    public function getStream()
    {
        return $this->stream;
    }
    public function getUrl()
    {
        return $this->url;
    }
    protected function write(array $record)
    {
        if (!is_resource($this->stream)) {
            if (null === $this->url || '' === $this->url) {
                throw new \LogicException('Missing stream url, the stream can not be opened. This may be caused by a premature call to close().');
            }
            $this->createDir();
            $this->errorMessage = null;
            set_error_handler(array($this, 'customErrorHandler'));
            $this->stream = fopen($this->url, 'a');
            if ($this->filePermission !== null) {
                @chmod($this->url, $this->filePermission);
            }
            restore_error_handler();
            if (!is_resource($this->stream)) {
                $this->stream = null;
                throw new \UnexpectedValueException(sprintf('The stream or file "%s" could not be opened: ' . $this->errorMessage, $this->url));
            }
        }
        if ($this->useLocking) {
            flock($this->stream, LOCK_EX);
        }
        fwrite($this->stream, (string) $record['formatted']);
        if ($this->useLocking) {
            flock($this->stream, LOCK_UN);
        }
    }
    private function customErrorHandler($code, $msg)
    {
        $this->errorMessage = preg_replace('{^(fopen|mkdir)\\(.*?\\): }', '', $msg);
    }
    private function getDirFromStream($stream)
    {
        $pos = strpos($stream, '://');
        if ($pos === false) {
            return dirname($stream);
        }
        if ('file://' === substr($stream, 0, 7)) {
            return dirname(substr($stream, 7));
        }
        return;
    }
    private function createDir()
    {
        if ($this->dirCreated) {
            return;
        }
        $dir = $this->getDirFromStream($this->url);
        if (null !== $dir && !is_dir($dir)) {
            $this->errorMessage = null;
            set_error_handler(array($this, 'customErrorHandler'));
            $status = mkdir($dir, 0777, true);
            restore_error_handler();
            if (false === $status) {
                throw new \UnexpectedValueException(sprintf('There is no existing directory at "%s" and its not buildable: ' . $this->errorMessage, $dir));
            }
        }
        $this->dirCreated = true;
    }
}
}

namespace Monolog\Handler {
use Monolog\Logger;
class RotatingFileHandler extends StreamHandler
{
    const FILE_PER_DAY = 'Y-m-d';
    const FILE_PER_MONTH = 'Y-m';
    const FILE_PER_YEAR = 'Y';
    protected $filename;
    protected $maxFiles;
    protected $mustRotate;
    protected $nextRotation;
    protected $filenameFormat;
    protected $dateFormat;
    public function __construct($filename, $maxFiles = 0, $level = Logger::DEBUG, $bubble = true, $filePermission = null, $useLocking = false)
    {
        $this->filename = $filename;
        $this->maxFiles = (int) $maxFiles;
        $this->nextRotation = new \DateTime('tomorrow');
        $this->filenameFormat = '{filename}-{date}';
        $this->dateFormat = 'Y-m-d';
        parent::__construct($this->getTimedFilename(), $level, $bubble, $filePermission, $useLocking);
    }
    public function close()
    {
        parent::close();
        if (true === $this->mustRotate) {
            $this->rotate();
        }
    }
    public function setFilenameFormat($filenameFormat, $dateFormat)
    {
        if (!preg_match('{^Y(([/_.-]?m)([/_.-]?d)?)?$}', $dateFormat)) {
            trigger_error('Invalid date format - format must be one of ' . 'RotatingFileHandler::FILE_PER_DAY ("Y-m-d"), RotatingFileHandler::FILE_PER_MONTH ("Y-m") ' . 'or RotatingFileHandler::FILE_PER_YEAR ("Y"), or you can set one of the ' . 'date formats using slashes, underscores and/or dots instead of dashes.', E_USER_DEPRECATED);
        }
        if (substr_count($filenameFormat, '{date}') === 0) {
            trigger_error('Invalid filename format - format should contain at least `{date}`, because otherwise rotating is impossible.', E_USER_DEPRECATED);
        }
        $this->filenameFormat = $filenameFormat;
        $this->dateFormat = $dateFormat;
        $this->url = $this->getTimedFilename();
        $this->close();
    }
    protected function write(array $record)
    {
        if (null === $this->mustRotate) {
            $this->mustRotate = !file_exists($this->url);
        }
        if ($this->nextRotation < $record['datetime']) {
            $this->mustRotate = true;
            $this->close();
        }
        parent::write($record);
    }
    protected function rotate()
    {
        $this->url = $this->getTimedFilename();
        $this->nextRotation = new \DateTime('tomorrow');
        if (0 === $this->maxFiles) {
            return;
        }
        $logFiles = glob($this->getGlobPattern());
        if ($this->maxFiles >= count($logFiles)) {
            return;
        }
        usort($logFiles, function ($a, $b) {
            return strcmp($b, $a);
        });
        foreach (array_slice($logFiles, $this->maxFiles) as $file) {
            if (is_writable($file)) {
                set_error_handler(function ($errno, $errstr, $errfile, $errline) {
                });
                unlink($file);
                restore_error_handler();
            }
        }
        $this->mustRotate = false;
    }
    protected function getTimedFilename()
    {
        $fileInfo = pathinfo($this->filename);
        $timedFilename = str_replace(array('{filename}', '{date}'), array($fileInfo['filename'], date($this->dateFormat)), $fileInfo['dirname'] . '/' . $this->filenameFormat);
        if (!empty($fileInfo['extension'])) {
            $timedFilename .= '.' . $fileInfo['extension'];
        }
        return $timedFilename;
    }
    protected function getGlobPattern()
    {
        $fileInfo = pathinfo($this->filename);
        $glob = str_replace(array('{filename}', '{date}'), array($fileInfo['filename'], '*'), $fileInfo['dirname'] . '/' . $this->filenameFormat);
        if (!empty($fileInfo['extension'])) {
            $glob .= '.' . $fileInfo['extension'];
        }
        return $glob;
    }
}
}

namespace Monolog\Handler {
use Monolog\Formatter\FormatterInterface;
interface HandlerInterface
{
    public function isHandling(array $record);
    public function handle(array $record);
    public function handleBatch(array $records);
    public function pushProcessor($callback);
    public function popProcessor();
    public function setFormatter(FormatterInterface $formatter);
    public function getFormatter();
}
}

namespace Monolog\Formatter {
interface FormatterInterface
{
    public function format(array $record);
    public function formatBatch(array $records);
}
}

namespace Monolog\Formatter {
use Exception;
class NormalizerFormatter implements FormatterInterface
{
    const SIMPLE_DATE = "Y-m-d H:i:s";
    protected $dateFormat;
    public function __construct($dateFormat = null)
    {
        $this->dateFormat = $dateFormat ?: static::SIMPLE_DATE;
        if (!function_exists('json_encode')) {
            throw new \RuntimeException('PHP\'s json extension is required to use Monolog\'s NormalizerFormatter');
        }
    }
    public function format(array $record)
    {
        return $this->normalize($record);
    }
    public function formatBatch(array $records)
    {
        foreach ($records as $key => $record) {
            $records[$key] = $this->format($record);
        }
        return $records;
    }
    protected function normalize($data)
    {
        if (null === $data || is_scalar($data)) {
            if (is_float($data)) {
                if (is_infinite($data)) {
                    return ($data > 0 ? '' : '-') . 'INF';
                }
                if (is_nan($data)) {
                    return 'NaN';
                }
            }
            return $data;
        }
        if (is_array($data) || $data instanceof \Traversable) {
            $normalized = array();
            $count = 1;
            foreach ($data as $key => $value) {
                if ($count++ >= 1000) {
                    $normalized['...'] = 'Over 1000 items, aborting normalization';
                    break;
                }
                $normalized[$key] = $this->normalize($value);
            }
            return $normalized;
        }
        if ($data instanceof \DateTime) {
            return $data->format($this->dateFormat);
        }
        if (is_object($data)) {
            if ($data instanceof Exception || PHP_VERSION_ID > 70000 && $data instanceof \Throwable) {
                return $this->normalizeException($data);
            }
            if (method_exists($data, '__toString') && !$data instanceof \JsonSerializable) {
                $value = $data->__toString();
            } else {
                $value = $this->toJson($data, true);
            }
            return sprintf("[object] (%s: %s)", get_class($data), $value);
        }
        if (is_resource($data)) {
            return sprintf('[resource] (%s)', get_resource_type($data));
        }
        return '[unknown(' . gettype($data) . ')]';
    }
    protected function normalizeException($e)
    {
        if (!$e instanceof Exception && !$e instanceof \Throwable) {
            throw new \InvalidArgumentException('Exception/Throwable expected, got ' . gettype($e) . ' / ' . get_class($e));
        }
        $data = array('class' => get_class($e), 'message' => $e->getMessage(), 'code' => $e->getCode(), 'file' => $e->getFile() . ':' . $e->getLine());
        if ($e instanceof \SoapFault) {
            if (isset($e->faultcode)) {
                $data['faultcode'] = $e->faultcode;
            }
            if (isset($e->faultactor)) {
                $data['faultactor'] = $e->faultactor;
            }
            if (isset($e->detail)) {
                $data['detail'] = $e->detail;
            }
        }
        $trace = $e->getTrace();
        foreach ($trace as $frame) {
            if (isset($frame['file'])) {
                $data['trace'][] = $frame['file'] . ':' . $frame['line'];
            } elseif (isset($frame['function']) && $frame['function'] === '{closure}') {
                $data['trace'][] = $frame['function'];
            } else {
                $data['trace'][] = $this->toJson($this->normalize($frame), true);
            }
        }
        if ($previous = $e->getPrevious()) {
            $data['previous'] = $this->normalizeException($previous);
        }
        return $data;
    }
    protected function toJson($data, $ignoreErrors = false)
    {
        if ($ignoreErrors) {
            return @$this->jsonEncode($data);
        }
        $json = $this->jsonEncode($data);
        if ($json === false) {
            $json = $this->handleJsonError(json_last_error(), $data);
        }
        return $json;
    }
    private function jsonEncode($data)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=')) {
            return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        return json_encode($data);
    }
    private function handleJsonError($code, $data)
    {
        if ($code !== JSON_ERROR_UTF8) {
            $this->throwEncodeError($code, $data);
        }
        if (is_string($data)) {
            $this->detectAndCleanUtf8($data);
        } elseif (is_array($data)) {
            array_walk_recursive($data, array($this, 'detectAndCleanUtf8'));
        } else {
            $this->throwEncodeError($code, $data);
        }
        $json = $this->jsonEncode($data);
        if ($json === false) {
            $this->throwEncodeError(json_last_error(), $data);
        }
        return $json;
    }
    private function throwEncodeError($code, $data)
    {
        switch ($code) {
            case JSON_ERROR_DEPTH:
                $msg = 'Maximum stack depth exceeded';
                break;
            case JSON_ERROR_STATE_MISMATCH:
                $msg = 'Underflow or the modes mismatch';
                break;
            case JSON_ERROR_CTRL_CHAR:
                $msg = 'Unexpected control character found';
                break;
            case JSON_ERROR_UTF8:
                $msg = 'Malformed UTF-8 characters, possibly incorrectly encoded';
                break;
            default:
                $msg = 'Unknown error';
        }
        throw new \RuntimeException('JSON encoding failed: ' . $msg . '. Encoding: ' . var_export($data, true));
    }
    public function detectAndCleanUtf8(&$data)
    {
        if (is_string($data) && !preg_match('//u', $data)) {
            $data = preg_replace_callback('/[\\x80-\\xFF]+/', function ($m) {
                return utf8_encode($m[0]);
            }, $data);
            $data = str_replace(array('¤', '¦', '¨', '´', '¸', '¼', '½', '¾'), array('€', 'Š', 'š', 'Ž', 'ž', 'Œ', 'œ', 'Ÿ'), $data);
        }
    }
}
}

namespace Monolog\Formatter {
class LineFormatter extends NormalizerFormatter
{
    const SIMPLE_FORMAT = "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n";
    protected $format;
    protected $allowInlineLineBreaks;
    protected $ignoreEmptyContextAndExtra;
    protected $includeStacktraces;
    public function __construct($format = null, $dateFormat = null, $allowInlineLineBreaks = false, $ignoreEmptyContextAndExtra = false)
    {
        $this->format = $format ?: static::SIMPLE_FORMAT;
        $this->allowInlineLineBreaks = $allowInlineLineBreaks;
        $this->ignoreEmptyContextAndExtra = $ignoreEmptyContextAndExtra;
        parent::__construct($dateFormat);
    }
    public function includeStacktraces($include = true)
    {
        $this->includeStacktraces = $include;
        if ($this->includeStacktraces) {
            $this->allowInlineLineBreaks = true;
        }
    }
    public function allowInlineLineBreaks($allow = true)
    {
        $this->allowInlineLineBreaks = $allow;
    }
    public function ignoreEmptyContextAndExtra($ignore = true)
    {
        $this->ignoreEmptyContextAndExtra = $ignore;
    }
    public function format(array $record)
    {
        $vars = parent::format($record);
        $output = $this->format;
        foreach ($vars['extra'] as $var => $val) {
            if (false !== strpos($output, '%extra.' . $var . '%')) {
                $output = str_replace('%extra.' . $var . '%', $this->stringify($val), $output);
                unset($vars['extra'][$var]);
            }
        }
        foreach ($vars['context'] as $var => $val) {
            if (false !== strpos($output, '%context.' . $var . '%')) {
                $output = str_replace('%context.' . $var . '%', $this->stringify($val), $output);
                unset($vars['context'][$var]);
            }
        }
        if ($this->ignoreEmptyContextAndExtra) {
            if (empty($vars['context'])) {
                unset($vars['context']);
                $output = str_replace('%context%', '', $output);
            }
            if (empty($vars['extra'])) {
                unset($vars['extra']);
                $output = str_replace('%extra%', '', $output);
            }
        }
        foreach ($vars as $var => $val) {
            if (false !== strpos($output, '%' . $var . '%')) {
                $output = str_replace('%' . $var . '%', $this->stringify($val), $output);
            }
        }
        return $output;
    }
    public function formatBatch(array $records)
    {
        $message = '';
        foreach ($records as $record) {
            $message .= $this->format($record);
        }
        return $message;
    }
    public function stringify($value)
    {
        return $this->replaceNewlines($this->convertToString($value));
    }
    protected function normalizeException($e)
    {
        if (!$e instanceof \Exception && !$e instanceof \Throwable) {
            throw new \InvalidArgumentException('Exception/Throwable expected, got ' . gettype($e) . ' / ' . get_class($e));
        }
        $previousText = '';
        if ($previous = $e->getPrevious()) {
            do {
                $previousText .= ', ' . get_class($previous) . '(code: ' . $previous->getCode() . '): ' . $previous->getMessage() . ' at ' . $previous->getFile() . ':' . $previous->getLine();
            } while ($previous = $previous->getPrevious());
        }
        $str = '[object] (' . get_class($e) . '(code: ' . $e->getCode() . '): ' . $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine() . $previousText . ')';
        if ($this->includeStacktraces) {
            $str .= "\n[stacktrace]\n" . $e->getTraceAsString();
        }
        return $str;
    }
    protected function convertToString($data)
    {
        if (null === $data || is_bool($data)) {
            return var_export($data, true);
        }
        if (is_scalar($data)) {
            return (string) $data;
        }
        if (version_compare(PHP_VERSION, '5.4.0', '>=')) {
            return $this->toJson($data, true);
        }
        return str_replace('\\/', '/', @json_encode($data));
    }
    protected function replaceNewlines($str)
    {
        if ($this->allowInlineLineBreaks) {
            return $str;
        }
        return str_replace(array("\r\n", "\r", "\n"), ' ', $str);
    }
}
}

namespace Symfony\Component\Finder {
class SplFileInfo extends \SplFileInfo
{
    private $relativePath;
    private $relativePathname;
    public function __construct($file, $relativePath, $relativePathname)
    {
        parent::__construct($file);
        $this->relativePath = $relativePath;
        $this->relativePathname = $relativePathname;
    }
    public function getRelativePath()
    {
        return $this->relativePath;
    }
    public function getRelativePathname()
    {
        return $this->relativePathname;
    }
    public function getContents()
    {
        $level = error_reporting(0);
        $content = file_get_contents($this->getPathname());
        error_reporting($level);
        if (false === $content) {
            $error = error_get_last();
            throw new \RuntimeException($error['message']);
        }
        return $content;
    }
}
}

namespace Symfony\Component\Finder\Iterator {
abstract class FilterIterator extends \FilterIterator
{
    public function rewind()
    {
        if (PHP_VERSION_ID > 50607 || PHP_VERSION_ID > 50523 && PHP_VERSION_ID < 50600) {
            parent::rewind();
            return;
        }
        $iterator = $this;
        while ($iterator instanceof \OuterIterator) {
            $innerIterator = $iterator->getInnerIterator();
            if ($innerIterator instanceof RecursiveDirectoryIterator) {
                if ($innerIterator->isRewindable()) {
                    $innerIterator->next();
                    $innerIterator->rewind();
                }
            } elseif ($innerIterator instanceof \FilesystemIterator) {
                $innerIterator->next();
                $innerIterator->rewind();
            }
            $iterator = $innerIterator;
        }
        parent::rewind();
    }
}
}

namespace Symfony\Component\Finder\Iterator {
abstract class MultiplePcreFilterIterator extends FilterIterator
{
    protected $matchRegexps = array();
    protected $noMatchRegexps = array();
    public function __construct(\Iterator $iterator, array $matchPatterns, array $noMatchPatterns)
    {
        foreach ($matchPatterns as $pattern) {
            $this->matchRegexps[] = $this->toRegex($pattern);
        }
        foreach ($noMatchPatterns as $pattern) {
            $this->noMatchRegexps[] = $this->toRegex($pattern);
        }
        parent::__construct($iterator);
    }
    protected function isAccepted($string)
    {
        foreach ($this->noMatchRegexps as $regex) {
            if (preg_match($regex, $string)) {
                return false;
            }
        }
        if ($this->matchRegexps) {
            foreach ($this->matchRegexps as $regex) {
                if (preg_match($regex, $string)) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }
    protected function isRegex($str)
    {
        if (preg_match('/^(.{3,}?)[imsxuADU]*$/', $str, $m)) {
            $start = substr($m[1], 0, 1);
            $end = substr($m[1], -1);
            if ($start === $end) {
                return !preg_match('/[*?[:alnum:] \\\\]/', $start);
            }
            foreach (array(array('{', '}'), array('(', ')'), array('[', ']'), array('<', '>')) as $delimiters) {
                if ($start === $delimiters[0] && $end === $delimiters[1]) {
                    return true;
                }
            }
        }
        return false;
    }
    protected abstract function toRegex($str);
}
}

namespace Symfony\Component\Finder\Iterator {
class PathFilterIterator extends MultiplePcreFilterIterator
{
    public function accept()
    {
        $filename = $this->current()->getRelativePathname();
        if ('\\' === DIRECTORY_SEPARATOR) {
            $filename = str_replace('\\', '/', $filename);
        }
        return $this->isAccepted($filename);
    }
    protected function toRegex($str)
    {
        return $this->isRegex($str) ? $str : '/' . preg_quote($str, '/') . '/';
    }
}
}

namespace Symfony\Component\Finder\Iterator {
class ExcludeDirectoryFilterIterator extends FilterIterator implements \RecursiveIterator
{
    private $iterator;
    private $isRecursive;
    private $excludedDirs = array();
    private $excludedPattern;
    public function __construct(\Iterator $iterator, array $directories)
    {
        $this->iterator = $iterator;
        $this->isRecursive = $iterator instanceof \RecursiveIterator;
        $patterns = array();
        foreach ($directories as $directory) {
            $directory = rtrim($directory, '/');
            if (!$this->isRecursive || false !== strpos($directory, '/')) {
                $patterns[] = preg_quote($directory, '#');
            } else {
                $this->excludedDirs[$directory] = true;
            }
        }
        if ($patterns) {
            $this->excludedPattern = '#(?:^|/)(?:' . implode('|', $patterns) . ')(?:/|$)#';
        }
        parent::__construct($iterator);
    }
    public function accept()
    {
        if ($this->isRecursive && isset($this->excludedDirs[$this->getFilename()]) && $this->isDir()) {
            return false;
        }
        if ($this->excludedPattern) {
            $path = $this->isDir() ? $this->current()->getRelativePathname() : $this->current()->getRelativePath();
            $path = str_replace('\\', '/', $path);
            return !preg_match($this->excludedPattern, $path);
        }
        return true;
    }
    public function hasChildren()
    {
        return $this->isRecursive && $this->iterator->hasChildren();
    }
    public function getChildren()
    {
        $children = new self($this->iterator->getChildren(), array());
        $children->excludedDirs = $this->excludedDirs;
        $children->excludedPattern = $this->excludedPattern;
        return $children;
    }
}
}

namespace Symfony\Component\Finder\Iterator {
use Symfony\Component\Finder\Exception\AccessDeniedException;
use Symfony\Component\Finder\SplFileInfo;
class RecursiveDirectoryIterator extends \RecursiveDirectoryIterator
{
    private $ignoreUnreadableDirs;
    private $rewindable;
    private $rootPath;
    private $subPath;
    private $directorySeparator = '/';
    public function __construct($path, $flags, $ignoreUnreadableDirs = false)
    {
        if ($flags & (self::CURRENT_AS_PATHNAME | self::CURRENT_AS_SELF)) {
            throw new \RuntimeException('This iterator only support returning current as fileinfo.');
        }
        parent::__construct($path, $flags);
        $this->ignoreUnreadableDirs = $ignoreUnreadableDirs;
        $this->rootPath = $path;
        if ('/' !== DIRECTORY_SEPARATOR && !($flags & self::UNIX_PATHS)) {
            $this->directorySeparator = DIRECTORY_SEPARATOR;
        }
    }
    public function current()
    {
        if (null === ($subPathname = $this->subPath)) {
            $subPathname = $this->subPath = (string) $this->getSubPath();
        }
        if ('' !== $subPathname) {
            $subPathname .= $this->directorySeparator;
        }
        $subPathname .= $this->getFilename();
        return new SplFileInfo($this->rootPath . $this->directorySeparator . $subPathname, $this->subPath, $subPathname);
    }
    public function getChildren()
    {
        try {
            $children = parent::getChildren();
            if ($children instanceof self) {
                $children->ignoreUnreadableDirs = $this->ignoreUnreadableDirs;
                $children->rewindable =& $this->rewindable;
                $children->rootPath = $this->rootPath;
            }
            return $children;
        } catch (\UnexpectedValueException $e) {
            if ($this->ignoreUnreadableDirs) {
                return new \RecursiveArrayIterator(array());
            } else {
                throw new AccessDeniedException($e->getMessage(), $e->getCode(), $e);
            }
        }
    }
    public function rewind()
    {
        if (false === $this->isRewindable()) {
            return;
        }
        if (PHP_VERSION_ID < 50523 || PHP_VERSION_ID >= 50600 && PHP_VERSION_ID < 50607) {
            parent::next();
        }
        parent::rewind();
    }
    public function isRewindable()
    {
        if (null !== $this->rewindable) {
            return $this->rewindable;
        }
        if ('' === $this->getPath()) {
            return $this->rewindable = false;
        }
        if (false !== ($stream = @opendir($this->getPath()))) {
            $infos = stream_get_meta_data($stream);
            closedir($stream);
            if ($infos['seekable']) {
                return $this->rewindable = true;
            }
        }
        return $this->rewindable = false;
    }
}
}

namespace Symfony\Component\Finder\Iterator {
class FileTypeFilterIterator extends FilterIterator
{
    const ONLY_FILES = 1;
    const ONLY_DIRECTORIES = 2;
    private $mode;
    public function __construct(\Iterator $iterator, $mode)
    {
        $this->mode = $mode;
        parent::__construct($iterator);
    }
    public function accept()
    {
        $fileinfo = $this->current();
        if (self::ONLY_DIRECTORIES === (self::ONLY_DIRECTORIES & $this->mode) && $fileinfo->isFile()) {
            return false;
        } elseif (self::ONLY_FILES === (self::ONLY_FILES & $this->mode) && $fileinfo->isDir()) {
            return false;
        }
        return true;
    }
}
}

namespace Symfony\Component\Finder\Iterator {
use Symfony\Component\Finder\Glob;
class FilenameFilterIterator extends MultiplePcreFilterIterator
{
    public function accept()
    {
        return $this->isAccepted($this->current()->getFilename());
    }
    protected function toRegex($str)
    {
        return $this->isRegex($str) ? $str : Glob::toRegex($str);
    }
}
}

namespace Symfony\Component\Finder {
use Symfony\Component\Finder\Comparator\DateComparator;
use Symfony\Component\Finder\Comparator\NumberComparator;
use Symfony\Component\Finder\Iterator\CustomFilterIterator;
use Symfony\Component\Finder\Iterator\DateRangeFilterIterator;
use Symfony\Component\Finder\Iterator\DepthRangeFilterIterator;
use Symfony\Component\Finder\Iterator\ExcludeDirectoryFilterIterator;
use Symfony\Component\Finder\Iterator\FilecontentFilterIterator;
use Symfony\Component\Finder\Iterator\FilenameFilterIterator;
use Symfony\Component\Finder\Iterator\SizeRangeFilterIterator;
use Symfony\Component\Finder\Iterator\SortableIterator;
class Finder implements \IteratorAggregate, \Countable
{
    const IGNORE_VCS_FILES = 1;
    const IGNORE_DOT_FILES = 2;
    private $mode = 0;
    private $names = array();
    private $notNames = array();
    private $exclude = array();
    private $filters = array();
    private $depths = array();
    private $sizes = array();
    private $followLinks = false;
    private $sort = false;
    private $ignore = 0;
    private $dirs = array();
    private $dates = array();
    private $iterators = array();
    private $contains = array();
    private $notContains = array();
    private $paths = array();
    private $notPaths = array();
    private $ignoreUnreadableDirs = false;
    private static $vcsPatterns = array('.svn', '_svn', 'CVS', '_darcs', '.arch-params', '.monotone', '.bzr', '.git', '.hg');
    public function __construct()
    {
        $this->ignore = static::IGNORE_VCS_FILES | static::IGNORE_DOT_FILES;
    }
    public static function create()
    {
        return new static();
    }
    public function directories()
    {
        $this->mode = Iterator\FileTypeFilterIterator::ONLY_DIRECTORIES;
        return $this;
    }
    public function files()
    {
        $this->mode = Iterator\FileTypeFilterIterator::ONLY_FILES;
        return $this;
    }
    public function depth($level)
    {
        $this->depths[] = new Comparator\NumberComparator($level);
        return $this;
    }
    public function date($date)
    {
        $this->dates[] = new Comparator\DateComparator($date);
        return $this;
    }
    public function name($pattern)
    {
        $this->names[] = $pattern;
        return $this;
    }
    public function notName($pattern)
    {
        $this->notNames[] = $pattern;
        return $this;
    }
    public function contains($pattern)
    {
        $this->contains[] = $pattern;
        return $this;
    }
    public function notContains($pattern)
    {
        $this->notContains[] = $pattern;
        return $this;
    }
    public function path($pattern)
    {
        $this->paths[] = $pattern;
        return $this;
    }
    public function notPath($pattern)
    {
        $this->notPaths[] = $pattern;
        return $this;
    }
    public function size($size)
    {
        $this->sizes[] = new Comparator\NumberComparator($size);
        return $this;
    }
    public function exclude($dirs)
    {
        $this->exclude = array_merge($this->exclude, (array) $dirs);
        return $this;
    }
    public function ignoreDotFiles($ignoreDotFiles)
    {
        if ($ignoreDotFiles) {
            $this->ignore |= static::IGNORE_DOT_FILES;
        } else {
            $this->ignore &= ~static::IGNORE_DOT_FILES;
        }
        return $this;
    }
    public function ignoreVCS($ignoreVCS)
    {
        if ($ignoreVCS) {
            $this->ignore |= static::IGNORE_VCS_FILES;
        } else {
            $this->ignore &= ~static::IGNORE_VCS_FILES;
        }
        return $this;
    }
    public static function addVCSPattern($pattern)
    {
        foreach ((array) $pattern as $p) {
            self::$vcsPatterns[] = $p;
        }
        self::$vcsPatterns = array_unique(self::$vcsPatterns);
    }
    public function sort(\Closure $closure)
    {
        $this->sort = $closure;
        return $this;
    }
    public function sortByName()
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_NAME;
        return $this;
    }
    public function sortByType()
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_TYPE;
        return $this;
    }
    public function sortByAccessedTime()
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_ACCESSED_TIME;
        return $this;
    }
    public function sortByChangedTime()
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_CHANGED_TIME;
        return $this;
    }
    public function sortByModifiedTime()
    {
        $this->sort = Iterator\SortableIterator::SORT_BY_MODIFIED_TIME;
        return $this;
    }
    public function filter(\Closure $closure)
    {
        $this->filters[] = $closure;
        return $this;
    }
    public function followLinks()
    {
        $this->followLinks = true;
        return $this;
    }
    public function ignoreUnreadableDirs($ignore = true)
    {
        $this->ignoreUnreadableDirs = (bool) $ignore;
        return $this;
    }
    public function in($dirs)
    {
        $resolvedDirs = array();
        foreach ((array) $dirs as $dir) {
            if (is_dir($dir)) {
                $resolvedDirs[] = $dir;
            } elseif ($glob = glob($dir, (defined('GLOB_BRACE') ? GLOB_BRACE : 0) | GLOB_ONLYDIR)) {
                $resolvedDirs = array_merge($resolvedDirs, $glob);
            } else {
                throw new \InvalidArgumentException(sprintf('The "%s" directory does not exist.', $dir));
            }
        }
        $this->dirs = array_merge($this->dirs, $resolvedDirs);
        return $this;
    }
    public function getIterator()
    {
        if (0 === count($this->dirs) && 0 === count($this->iterators)) {
            throw new \LogicException('You must call one of in() or append() methods before iterating over a Finder.');
        }
        if (1 === count($this->dirs) && 0 === count($this->iterators)) {
            return $this->searchInDirectory($this->dirs[0]);
        }
        $iterator = new \AppendIterator();
        foreach ($this->dirs as $dir) {
            $iterator->append($this->searchInDirectory($dir));
        }
        foreach ($this->iterators as $it) {
            $iterator->append($it);
        }
        return $iterator;
    }
    public function append($iterator)
    {
        if ($iterator instanceof \IteratorAggregate) {
            $this->iterators[] = $iterator->getIterator();
        } elseif ($iterator instanceof \Iterator) {
            $this->iterators[] = $iterator;
        } elseif ($iterator instanceof \Traversable || is_array($iterator)) {
            $it = new \ArrayIterator();
            foreach ($iterator as $file) {
                $it->append($file instanceof \SplFileInfo ? $file : new \SplFileInfo($file));
            }
            $this->iterators[] = $it;
        } else {
            throw new \InvalidArgumentException('Finder::append() method wrong argument type.');
        }
        return $this;
    }
    public function count()
    {
        return iterator_count($this->getIterator());
    }
    private function searchInDirectory($dir)
    {
        if (static::IGNORE_VCS_FILES === (static::IGNORE_VCS_FILES & $this->ignore)) {
            $this->exclude = array_merge($this->exclude, self::$vcsPatterns);
        }
        if (static::IGNORE_DOT_FILES === (static::IGNORE_DOT_FILES & $this->ignore)) {
            $this->notPaths[] = '#(^|/)\\..+(/|$)#';
        }
        $minDepth = 0;
        $maxDepth = PHP_INT_MAX;
        foreach ($this->depths as $comparator) {
            switch ($comparator->getOperator()) {
                case '>':
                    $minDepth = $comparator->getTarget() + 1;
                    break;
                case '>=':
                    $minDepth = $comparator->getTarget();
                    break;
                case '<':
                    $maxDepth = $comparator->getTarget() - 1;
                    break;
                case '<=':
                    $maxDepth = $comparator->getTarget();
                    break;
                default:
                    $minDepth = $maxDepth = $comparator->getTarget();
            }
        }
        $flags = \RecursiveDirectoryIterator::SKIP_DOTS;
        if ($this->followLinks) {
            $flags |= \RecursiveDirectoryIterator::FOLLOW_SYMLINKS;
        }
        $iterator = new Iterator\RecursiveDirectoryIterator($dir, $flags, $this->ignoreUnreadableDirs);
        if ($this->exclude) {
            $iterator = new Iterator\ExcludeDirectoryFilterIterator($iterator, $this->exclude);
        }
        $iterator = new \RecursiveIteratorIterator($iterator, \RecursiveIteratorIterator::SELF_FIRST);
        if ($minDepth > 0 || $maxDepth < PHP_INT_MAX) {
            $iterator = new Iterator\DepthRangeFilterIterator($iterator, $minDepth, $maxDepth);
        }
        if ($this->mode) {
            $iterator = new Iterator\FileTypeFilterIterator($iterator, $this->mode);
        }
        if ($this->names || $this->notNames) {
            $iterator = new Iterator\FilenameFilterIterator($iterator, $this->names, $this->notNames);
        }
        if ($this->contains || $this->notContains) {
            $iterator = new Iterator\FilecontentFilterIterator($iterator, $this->contains, $this->notContains);
        }
        if ($this->sizes) {
            $iterator = new Iterator\SizeRangeFilterIterator($iterator, $this->sizes);
        }
        if ($this->dates) {
            $iterator = new Iterator\DateRangeFilterIterator($iterator, $this->dates);
        }
        if ($this->filters) {
            $iterator = new Iterator\CustomFilterIterator($iterator, $this->filters);
        }
        if ($this->paths || $this->notPaths) {
            $iterator = new Iterator\PathFilterIterator($iterator, $this->paths, $this->notPaths);
        }
        if ($this->sort) {
            $iteratorAggregate = new Iterator\SortableIterator($iterator, $this->sort);
            $iterator = $iteratorAggregate->getIterator();
        }
        return $iterator;
    }
}
}

namespace Symfony\Component\Finder {
class Glob
{
    public static function toRegex($glob, $strictLeadingDot = true, $strictWildcardSlash = true, $delimiter = '#')
    {
        $firstByte = true;
        $escaping = false;
        $inCurlies = 0;
        $regex = '';
        $sizeGlob = strlen($glob);
        for ($i = 0; $i < $sizeGlob; ++$i) {
            $car = $glob[$i];
            if ($firstByte) {
                if ($strictLeadingDot && '.' !== $car) {
                    $regex .= '(?=[^\\.])';
                }
                $firstByte = false;
            }
            if ('/' === $car) {
                $firstByte = true;
            }
            if ($delimiter === $car || '.' === $car || '(' === $car || ')' === $car || '|' === $car || '+' === $car || '^' === $car || '$' === $car) {
                $regex .= "\\{$car}";
            } elseif ('*' === $car) {
                $regex .= $escaping ? '\\*' : ($strictWildcardSlash ? '[^/]*' : '.*');
            } elseif ('?' === $car) {
                $regex .= $escaping ? '\\?' : ($strictWildcardSlash ? '[^/]' : '.');
            } elseif ('{' === $car) {
                $regex .= $escaping ? '\\{' : '(';
                if (!$escaping) {
                    ++$inCurlies;
                }
            } elseif ('}' === $car && $inCurlies) {
                $regex .= $escaping ? '}' : ')';
                if (!$escaping) {
                    --$inCurlies;
                }
            } elseif (',' === $car && $inCurlies) {
                $regex .= $escaping ? ',' : '|';
            } elseif ('\\' === $car) {
                if ($escaping) {
                    $regex .= '\\\\';
                    $escaping = false;
                } else {
                    $escaping = true;
                }
                continue;
            } else {
                $regex .= $car;
            }
            $escaping = false;
        }
        return $delimiter . '^' . $regex . '$' . $delimiter;
    }
}
}

namespace Dotenv {
class Dotenv
{
    protected $filePath;
    protected $loader;
    public function __construct($path, $file = '.env')
    {
        $this->filePath = $this->getFilePath($path, $file);
        $this->loader = new Loader($this->filePath, true);
    }
    public function load()
    {
        return $this->loadData();
    }
    public function overload()
    {
        return $this->loadData(true);
    }
    protected function getFilePath($path, $file)
    {
        if (!is_string($file)) {
            $file = '.env';
        }
        $filePath = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $file;
        return $filePath;
    }
    protected function loadData($overload = false)
    {
        $this->loader = new Loader($this->filePath, !$overload);
        return $this->loader->load();
    }
    public function required($variable)
    {
        return new Validator((array) $variable, $this->loader);
    }
}
}

namespace FastRoute\RouteParser {
use FastRoute\BadRouteException;
use FastRoute\RouteParser;
class Std implements RouteParser
{
    const VARIABLE_REGEX = <<<'REGEX'
\{
    \s* ([a-zA-Z_][a-zA-Z0-9_-]*) \s*
    (?:
        : \s* ([^{}]*(?:\{(?-1)\}[^{}]*)*)
    )?
\}
REGEX;
    const DEFAULT_DISPATCH_REGEX = '[^/]+';
    public function parse($route)
    {
        $routeWithoutClosingOptionals = rtrim($route, ']');
        $numOptionals = strlen($route) - strlen($routeWithoutClosingOptionals);
        $segments = preg_split('~' . self::VARIABLE_REGEX . '(*SKIP)(*F) | \\[~x', $routeWithoutClosingOptionals);
        if ($numOptionals !== count($segments) - 1) {
            if (preg_match('~' . self::VARIABLE_REGEX . '(*SKIP)(*F) | \\]~x', $routeWithoutClosingOptionals)) {
                throw new BadRouteException("Optional segments can only occur at the end of a route");
            }
            throw new BadRouteException("Number of opening '[' and closing ']' does not match");
        }
        $currentRoute = '';
        $routeDatas = [];
        foreach ($segments as $n => $segment) {
            if ($segment === '' && $n !== 0) {
                throw new BadRouteException("Empty optional part");
            }
            $currentRoute .= $segment;
            $routeDatas[] = $this->parsePlaceholders($currentRoute);
        }
        return $routeDatas;
    }
    private function parsePlaceholders($route)
    {
        if (!preg_match_all('~' . self::VARIABLE_REGEX . '~x', $route, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER)) {
            return [$route];
        }
        $offset = 0;
        $routeData = [];
        foreach ($matches as $set) {
            if ($set[0][1] > $offset) {
                $routeData[] = substr($route, $offset, $set[0][1] - $offset);
            }
            $routeData[] = [$set[1][0], isset($set[2]) ? trim($set[2][0]) : self::DEFAULT_DISPATCH_REGEX];
            $offset = $set[0][1] + strlen($set[0][0]);
        }
        if ($offset != strlen($route)) {
            $routeData[] = substr($route, $offset);
        }
        return $routeData;
    }
}
}

namespace FastRoute {
class BadRouteException extends \LogicException
{
}
}

namespace FastRoute\DataGenerator {
use FastRoute\DataGenerator;
use FastRoute\BadRouteException;
use FastRoute\Route;
abstract class RegexBasedAbstract implements DataGenerator
{
    protected $staticRoutes = [];
    protected $methodToRegexToRoutesMap = [];
    protected abstract function getApproxChunkSize();
    protected abstract function processChunk($regexToRoutesMap);
    public function addRoute($httpMethod, $routeData, $handler)
    {
        if ($this->isStaticRoute($routeData)) {
            $this->addStaticRoute($httpMethod, $routeData, $handler);
        } else {
            $this->addVariableRoute($httpMethod, $routeData, $handler);
        }
    }
    public function getData()
    {
        if (empty($this->methodToRegexToRoutesMap)) {
            return [$this->staticRoutes, []];
        }
        return [$this->staticRoutes, $this->generateVariableRouteData()];
    }
    private function generateVariableRouteData()
    {
        $data = [];
        foreach ($this->methodToRegexToRoutesMap as $method => $regexToRoutesMap) {
            $chunkSize = $this->computeChunkSize(count($regexToRoutesMap));
            $chunks = array_chunk($regexToRoutesMap, $chunkSize, true);
            $data[$method] = array_map([$this, 'processChunk'], $chunks);
        }
        return $data;
    }
    private function computeChunkSize($count)
    {
        $numParts = max(1, round($count / $this->getApproxChunkSize()));
        return ceil($count / $numParts);
    }
    private function isStaticRoute($routeData)
    {
        return count($routeData) === 1 && is_string($routeData[0]);
    }
    private function addStaticRoute($httpMethod, $routeData, $handler)
    {
        $routeStr = $routeData[0];
        if (isset($this->staticRoutes[$httpMethod][$routeStr])) {
            throw new BadRouteException(sprintf('Cannot register two routes matching "%s" for method "%s"', $routeStr, $httpMethod));
        }
        if (isset($this->methodToRegexToRoutesMap[$httpMethod])) {
            foreach ($this->methodToRegexToRoutesMap[$httpMethod] as $route) {
                if ($route->matches($routeStr)) {
                    throw new BadRouteException(sprintf('Static route "%s" is shadowed by previously defined variable route "%s" for method "%s"', $routeStr, $route->regex, $httpMethod));
                }
            }
        }
        $this->staticRoutes[$httpMethod][$routeStr] = $handler;
    }
    private function addVariableRoute($httpMethod, $routeData, $handler)
    {
        list($regex, $variables) = $this->buildRegexForRoute($routeData);
        if (isset($this->methodToRegexToRoutesMap[$httpMethod][$regex])) {
            throw new BadRouteException(sprintf('Cannot register two routes matching "%s" for method "%s"', $regex, $httpMethod));
        }
        $this->methodToRegexToRoutesMap[$httpMethod][$regex] = new Route($httpMethod, $handler, $regex, $variables);
    }
    private function buildRegexForRoute($routeData)
    {
        $regex = '';
        $variables = [];
        foreach ($routeData as $part) {
            if (is_string($part)) {
                $regex .= preg_quote($part, '~');
                continue;
            }
            list($varName, $regexPart) = $part;
            if (isset($variables[$varName])) {
                throw new BadRouteException(sprintf('Cannot use the same placeholder "%s" twice', $varName));
            }
            if ($this->regexHasCapturingGroups($regexPart)) {
                throw new BadRouteException(sprintf('Regex "%s" for parameter "%s" contains a capturing group', $regexPart, $varName));
            }
            $variables[$varName] = $varName;
            $regex .= '(' . $regexPart . ')';
        }
        return [$regex, $variables];
    }
    private function regexHasCapturingGroups($regex)
    {
        if (false === strpos($regex, '(')) {
            return false;
        }
        return preg_match('~
                (?:
                    \\(\\?\\(
                  | \\[ [^\\]\\\\]* (?: \\\\ . [^\\]\\\\]* )* \\]
                  | \\\\ .
                ) (*SKIP)(*FAIL) |
                \\(
                (?!
                    \\? (?! <(?![!=]) | P< | \' )
                  | \\*
                )
            ~x', $regex);
    }
}
}

namespace FastRoute\DataGenerator {
class MarkBased extends RegexBasedAbstract
{
    protected function getApproxChunkSize()
    {
        return 30;
    }
    protected function processChunk($regexToRoutesMap)
    {
        $routeMap = [];
        $regexes = [];
        $markName = 'a';
        foreach ($regexToRoutesMap as $regex => $route) {
            $regexes[] = $regex . '(*MARK:' . $markName . ')';
            $routeMap[$markName] = [$route->handler, $route->variables];
            ++$markName;
        }
        $regex = '~^(?|' . implode('|', $regexes) . ')$~';
        return ['regex' => $regex, 'routeMap' => $routeMap];
    }
}
}

namespace FastRoute\DataGenerator {
class GroupPosBased extends RegexBasedAbstract
{
    protected function getApproxChunkSize()
    {
        return 10;
    }
    protected function processChunk($regexToRoutesMap)
    {
        $routeMap = [];
        $regexes = [];
        $offset = 1;
        foreach ($regexToRoutesMap as $regex => $route) {
            $regexes[] = $regex;
            $routeMap[$offset] = [$route->handler, $route->variables];
            $offset += count($route->variables);
        }
        $regex = '~^(?:' . implode('|', $regexes) . ')$~';
        return ['regex' => $regex, 'routeMap' => $routeMap];
    }
}
}

namespace FastRoute\DataGenerator {
class GroupCountBased extends RegexBasedAbstract
{
    protected function getApproxChunkSize()
    {
        return 10;
    }
    protected function processChunk($regexToRoutesMap)
    {
        $routeMap = [];
        $regexes = [];
        $numGroups = 0;
        foreach ($regexToRoutesMap as $regex => $route) {
            $numVariables = count($route->variables);
            $numGroups = max($numGroups, $numVariables);
            $regexes[] = $regex . str_repeat('()', $numGroups - $numVariables);
            $routeMap[$numGroups + 1] = [$route->handler, $route->variables];
            ++$numGroups;
        }
        $regex = '~^(?|' . implode('|', $regexes) . ')$~';
        return ['regex' => $regex, 'routeMap' => $routeMap];
    }
}
}

namespace FastRoute\DataGenerator {
class CharCountBased extends RegexBasedAbstract
{
    protected function getApproxChunkSize()
    {
        return 30;
    }
    protected function processChunk($regexToRoutesMap)
    {
        $routeMap = [];
        $regexes = [];
        $suffixLen = 0;
        $suffix = '';
        $count = count($regexToRoutesMap);
        foreach ($regexToRoutesMap as $regex => $route) {
            $suffixLen++;
            $suffix .= "\t";
            $regexes[] = '(?:' . $regex . '/(\\t{' . $suffixLen . '})\\t{' . ($count - $suffixLen) . '})';
            $routeMap[$suffix] = [$route->handler, $route->variables];
        }
        $regex = '~^(?|' . implode('|', $regexes) . ')$~';
        return ['regex' => $regex, 'suffix' => '/' . $suffix, 'routeMap' => $routeMap];
    }
}
}

namespace FastRoute {
class RouteCollector
{
    private $routeParser;
    private $dataGenerator;
    public function __construct(RouteParser $routeParser, DataGenerator $dataGenerator)
    {
        $this->routeParser = $routeParser;
        $this->dataGenerator = $dataGenerator;
    }
    public function addRoute($httpMethod, $route, $handler)
    {
        $routeDatas = $this->routeParser->parse($route);
        foreach ((array) $httpMethod as $method) {
            foreach ($routeDatas as $routeData) {
                $this->dataGenerator->addRoute($method, $routeData, $handler);
            }
        }
    }
    public function getData()
    {
        return $this->dataGenerator->getData();
    }
}
}

namespace FastRoute {
class Route
{
    public $httpMethod;
    public $regex;
    public $variables;
    public $handler;
    public function __construct($httpMethod, $handler, $regex, $variables)
    {
        $this->httpMethod = $httpMethod;
        $this->handler = $handler;
        $this->regex = $regex;
        $this->variables = $variables;
    }
    public function matches($str)
    {
        $regex = '~^' . $this->regex . '$~';
        return (bool) preg_match($regex, $str);
    }
}
}

namespace FastRoute {
interface DataGenerator
{
    public function addRoute($httpMethod, $routeData, $handler);
    public function getData();
}
}

namespace FastRoute {
interface RouteParser
{
    public function parse($route);
}
}

namespace FastRoute {
interface Dispatcher
{
    const NOT_FOUND = 0;
    const FOUND = 1;
    const METHOD_NOT_ALLOWED = 2;
    public function dispatch($httpMethod, $uri);
}
}

namespace FastRoute\Dispatcher {
use FastRoute\Dispatcher;
abstract class RegexBasedAbstract implements Dispatcher
{
    protected $staticRouteMap;
    protected $variableRouteData;
    protected abstract function dispatchVariableRoute($routeData, $uri);
    public function dispatch($httpMethod, $uri)
    {
        if (isset($this->staticRouteMap[$httpMethod][$uri])) {
            $handler = $this->staticRouteMap[$httpMethod][$uri];
            return [self::FOUND, $handler, []];
        }
        $varRouteData = $this->variableRouteData;
        if (isset($varRouteData[$httpMethod])) {
            $result = $this->dispatchVariableRoute($varRouteData[$httpMethod], $uri);
            if ($result[0] === self::FOUND) {
                return $result;
            }
        }
        if ($httpMethod === 'HEAD') {
            if (isset($this->staticRouteMap['GET'][$uri])) {
                $handler = $this->staticRouteMap['GET'][$uri];
                return [self::FOUND, $handler, []];
            }
            if (isset($varRouteData['GET'])) {
                $result = $this->dispatchVariableRoute($varRouteData['GET'], $uri);
                if ($result[0] === self::FOUND) {
                    return $result;
                }
            }
        }
        if (isset($this->staticRouteMap['*'][$uri])) {
            $handler = $this->staticRouteMap['*'][$uri];
            return [self::FOUND, $handler, []];
        }
        if (isset($varRouteData['*'])) {
            $result = $this->dispatchVariableRoute($varRouteData['*'], $uri);
            if ($result[0] === self::FOUND) {
                return $result;
            }
        }
        $allowedMethods = [];
        foreach ($this->staticRouteMap as $method => $uriMap) {
            if ($method !== $httpMethod && isset($uriMap[$uri])) {
                $allowedMethods[] = $method;
            }
        }
        foreach ($varRouteData as $method => $routeData) {
            if ($method === $httpMethod) {
                continue;
            }
            $result = $this->dispatchVariableRoute($routeData, $uri);
            if ($result[0] === self::FOUND) {
                $allowedMethods[] = $method;
            }
        }
        if ($allowedMethods) {
            return [self::METHOD_NOT_ALLOWED, $allowedMethods];
        } else {
            return [self::NOT_FOUND];
        }
    }
}
}

namespace FastRoute\Dispatcher {
class MarkBased extends RegexBasedAbstract
{
    public function __construct($data)
    {
        list($this->staticRouteMap, $this->variableRouteData) = $data;
    }
    protected function dispatchVariableRoute($routeData, $uri)
    {
        foreach ($routeData as $data) {
            if (!preg_match($data['regex'], $uri, $matches)) {
                continue;
            }
            list($handler, $varNames) = $data['routeMap'][$matches['MARK']];
            $vars = [];
            $i = 0;
            foreach ($varNames as $varName) {
                $vars[$varName] = $matches[++$i];
            }
            return [self::FOUND, $handler, $vars];
        }
        return [self::NOT_FOUND];
    }
}
}

namespace FastRoute\Dispatcher {
class GroupPosBased extends RegexBasedAbstract
{
    public function __construct($data)
    {
        list($this->staticRouteMap, $this->variableRouteData) = $data;
    }
    protected function dispatchVariableRoute($routeData, $uri)
    {
        foreach ($routeData as $data) {
            if (!preg_match($data['regex'], $uri, $matches)) {
                continue;
            }
            for ($i = 1; '' === $matches[$i]; ++$i) {
            }
            list($handler, $varNames) = $data['routeMap'][$i];
            $vars = [];
            foreach ($varNames as $varName) {
                $vars[$varName] = $matches[$i++];
            }
            return [self::FOUND, $handler, $vars];
        }
        return [self::NOT_FOUND];
    }
}
}

namespace FastRoute\Dispatcher {
class GroupCountBased extends RegexBasedAbstract
{
    public function __construct($data)
    {
        list($this->staticRouteMap, $this->variableRouteData) = $data;
    }
    protected function dispatchVariableRoute($routeData, $uri)
    {
        foreach ($routeData as $data) {
            if (!preg_match($data['regex'], $uri, $matches)) {
                continue;
            }
            list($handler, $varNames) = $data['routeMap'][count($matches)];
            $vars = [];
            $i = 0;
            foreach ($varNames as $varName) {
                $vars[$varName] = $matches[++$i];
            }
            return [self::FOUND, $handler, $vars];
        }
        return [self::NOT_FOUND];
    }
}
}

namespace FastRoute\Dispatcher {
class CharCountBased extends RegexBasedAbstract
{
    public function __construct($data)
    {
        list($this->staticRouteMap, $this->variableRouteData) = $data;
    }
    protected function dispatchVariableRoute($routeData, $uri)
    {
        foreach ($routeData as $data) {
            if (!preg_match($data['regex'], $uri . $data['suffix'], $matches)) {
                continue;
            }
            list($handler, $varNames) = $data['routeMap'][end($matches)];
            $vars = [];
            $i = 0;
            foreach ($varNames as $varName) {
                $vars[$varName] = $matches[++$i];
            }
            return [self::FOUND, $handler, $vars];
        }
        return [self::NOT_FOUND];
    }
}
}

namespace FastRoute {
if (!function_exists('FastRoute\\simpleDispatcher')) {
    function simpleDispatcher(callable $routeDefinitionCallback, array $options = [])
    {
        $options += ['routeParser' => 'FastRoute\\RouteParser\\Std', 'dataGenerator' => 'FastRoute\\DataGenerator\\GroupCountBased', 'dispatcher' => 'FastRoute\\Dispatcher\\GroupCountBased', 'routeCollector' => 'FastRoute\\RouteCollector'];
        $routeCollector = new $options['routeCollector'](new $options['routeParser'](), new $options['dataGenerator']());
        $routeDefinitionCallback($routeCollector);
        return new $options['dispatcher']($routeCollector->getData());
    }
    function cachedDispatcher(callable $routeDefinitionCallback, array $options = [])
    {
        $options += ['routeParser' => 'FastRoute\\RouteParser\\Std', 'dataGenerator' => 'FastRoute\\DataGenerator\\GroupCountBased', 'dispatcher' => 'FastRoute\\Dispatcher\\GroupCountBased', 'routeCollector' => 'FastRoute\\RouteCollector', 'cacheDisabled' => false];
        if (!isset($options['cacheFile'])) {
            throw new \LogicException('Must specify "cacheFile" option');
        }
        if (!$options['cacheDisabled'] && file_exists($options['cacheFile'])) {
            $dispatchData = (require $options['cacheFile']);
            if (!is_array($dispatchData)) {
                throw new \RuntimeException('Invalid cache file "' . $options['cacheFile'] . '"');
            }
            return new $options['dispatcher']($dispatchData);
        }
        $routeCollector = new $options['routeCollector'](new $options['routeParser'](), new $options['dataGenerator']());
        $routeDefinitionCallback($routeCollector);
        $dispatchData = $routeCollector->getData();
        file_put_contents($options['cacheFile'], '<?php return ' . var_export($dispatchData, true) . ';');
        return new $options['dispatcher']($dispatchData);
    }
}
}

