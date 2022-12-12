<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register', 'logout', 'getMe', 'getAll', 'update']]);
    }

    public function login(Request $request)
    {
        $validate = $this->my_validate($request->all(), [
            'name'           => 'required|string',
            'phone'          => 'required|numeric',
            'voucher_type'   => 'required|string',
            'email'          => 'string|email',
        ]);

        if ($validate !== true) return $validate;

        $credentials = $request->only('phone', 'password');

        $token = Auth::attempt($credentials);
        if (!$token) {
            return self::authFailed();
        }

        $user = Auth::user();
        return self::successResponse([
            'user' => $user,
            'authorization' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);

    }

    public function register(Request $request){

        $validate = $this->my_validate($request->all(), [
            'name'           => 'required|string|max:255',
            'phone'          => 'required|numeric|unique:users',
            'voucher_type'   => 'required|string|max:255',
            'email'          => 'string|email|max:255',
            'password'       => 'required|string|min:8',
        ]);

        if ($validate !== true) return $validate;

        $user = User::create([
            'name' => $request->name,
            'phone' => $request->phone,
            'voucher_type' => $request->voucher_type,
            'email' => $request->email ?? null,
            'password' => Hash::make($request->password),
        ]);

        $token = Auth::login($user);
        return self::successResponse([
            'message' => 'User created successfully',
            'user' => $user,
            'authorization' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }

    public function logout()
    {
        if(!auth()->check()) return self::authFailed();

        Auth::logout();
        return self::successResponse([
            'message' => 'Successfully logged out',
        ]);
    }

    public function refresh()
    {
        if(!auth()->check()) return self::authFailed();

        return response()->json([
            'status' => 'success',
            'user' => Auth::user(),
            'authorisation' => [
                'token' => Auth::refresh(),
                'type' => 'bearer',
            ]
        ]);
    }

    public function update(Request $request){

        if(!auth()->check()) return self::authFailed();

        $validate = $this->my_validate($request->all(), [
            'name'           => 'string|max:255',
            'phone'          => 'numeric|unique:users',
            'voucher_type'   => 'string|max:255',
            'email'          => 'email|max:255',
            'password'       => 'string|min:8',
        ]);

        if ($validate !== true) return $validate;

        $userId = Auth::user()->id;

        $user = User::where('id', '=', $userId)->get()->first();

        if($request->has('name')) $user->name = $request->name;
        if($request->has('phone')) $user->phone = $request->phone;
        if($request->has('voucher_type')) $user->voucher_type = $request->voucher_type;
        if($request->has('email')) $user->email = $request->email;
        if($request->has('password')) $user->password = $request->password;

        $user->save();

        return self::successResponse([
            'message' => 'User updated successfully',
            'user' => $user,
        ]);
    }

    public function getMe(Request $request)
    {
        if(!auth()->check()) return self::authFailed();

        $user = Auth::user();

        return self::successResponse([
            'user' => $user,
        ]);
    }

    public function getAll(Request $request)
    {
        if(!auth()->check()) return self::authFailed();
        return self::successResponse(User::paginate(15));
    }

    public function my_validate(array $params, array $rules)
    {
        $validate = Validator::make($params,$rules);

        if ($validate->fails())
        {
            return self::validationError($validate);
        }

        return true;
    }

    public function validationError($validation)
    {
        return [
            'status' => false,
            'error' => [
                'messages' => array_map(function ($errors){
                    return $errors[0];
                },$validation->messages()->toArray()),
                'message' => $validation->errors()->first(),
            ]
        ];
    }

    public static function successResponse($data)
    {
        return [
            'status' => true,
            'result' => $data
        ];
    }

    public static function authFailed()
    {
        return [
            'status' => false,
            'error' => [
                'message' => "Authorization failed!"
            ]
        ];
    }

}
