<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreLoginRequest;
use App\Mail\SendMailOTP;
use Carbon\Carbon;
use Illuminate\Cache\Events\RetrievingKey;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function Verification()
    {
        $user = Auth::user();
        $otp = rand(100000, 999999);
        $email = Mail::to($user->email)->send(new SendMailOTP($otp, $user->first_name));
        return $this->response(code: 200);
    }
    public function login(StoreLoginRequest $request)
    {
        $request = $request->validated();
        $Auth = Auth::attempt($request);
        if ($Auth) {
            $user = Auth::user();
            $token = $user->createToken('front-end', $user->role, Carbon::now()->addDays(7))->plainTextToken;
            $user['token'] = $token;
            return $this->response(code: 200, data: $user);
        } else {
            return $this->response(code: 401);
        }
    }
    public function logout(Request $request)
    {
        $token = $request->bearerToken();
        $currentToken = PersonalAccessToken::findToken($token);
        if ($currentToken) {
            if ($currentToken->delete()) {
                return $this->response(code: 202, msg: 'Logged out successfully');
            }
        } else {
            return $this->response(code: 404, msg: 'Cannot log out at the moment');
        }
    }
    public function logout_all()
    {
        $logout = Auth::user()->tokens()->delete();
        if ($logout) {
            return $this->response(code: 202, msg: 'Logged out from all devices successfully');
        } else {
            return $this->response(code: 404, msg: 'Cannot log out at the moment');
        }
    }
}
