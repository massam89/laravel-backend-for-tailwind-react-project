<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Validator;
use GuzzleHttp\Client;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct() 
    {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'checkUsername']]);
    }
    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */

     /**
     * Log in the user.
     *
     * @bodyParam   username    string  required    The username of the  user. Example: ali
     * @bodyParam   password    string  required    The password of the  user.   Example: secret
     *
     */

    public function login(Request $request)
    {
    	$validator = Validator::make($request->all(), [
            'username' => 'required',
            'password' => 'required|string|min:6',
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        if (! $token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->createNewToken($token);
    }

    /**
     * register the user.
     *
     * @bodyParam   name    string  required    The name of the  user.  Example: ali
     * @bodyParam   username    string  required    The username of the  user. Example: username
     * @bodyParam   password    string  required    The password of the  user.   Example: secret
     * 
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request) 
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|between:2,100',
            'username' => 'required|max:255|regex:/\w*$/|unique:users,username',
            'password' => 'required|string|confirmed|min:6',
        ]);
        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }
        $user = User::create(array_merge(
                    $validator->validated(),
                    ['password' => bcrypt($request->password)]
                ));
        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user
        ], 201);
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @header authorization Example:bearer eyJ0eXAiOiJKV...
     * 
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout() 
    {
        auth()->logout();
        return response()->json(['message' => 'User successfully signed out']);
    }
    /**
     * Refresh a token.
     *
     *  @bodyParam   access_token    string  required    access_token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh() 
    {
        return $this->createNewToken(auth()->refresh());
    }

    /**
     * Get the authenticated User's information.
     * 
     * @header authorization Example:bearer eyJ0eXAiOiJKV...
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile() 
    {
        return response()->json(auth()->user());
    }
    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function createNewToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }

    /**
     * Check username is unique.
     * 
     *  @bodyParam   username    string  required    username
     *
     */

    public function checkUsername(Request $request) 
    {    
        if (User::where('username', $request->username)->exists()) {
            return 'true';
        } else {
            return 'false';
        }
    }

    /**
     * get customer users from another sources "randomuser.me"
     * 
     * @header authorization Example:bearer eyJ0eXAiOiJKV...
     */

    public function customerData () 
    {
        $client = new Client(['base_uri' => 'https://randomuser.me/']);
        $res = $client->request('GET', '/api/?results=20');
        return $res->getBody();
    }
}