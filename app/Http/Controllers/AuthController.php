<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function register(Request $request){
        return User::create([
            'first_name' => $request->input('first_name'),
            'last_name' => $request->input('last_name'),
            'username' => $request->input('username'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password'))
        ]);
    }

    public function login(Request $request){
        $isAuth = Auth::attempt([
            'username' => $request->input('email'),
            'password' => $request->input('password')
        ]);

        if(!$isAuth){
            return response([
                'message' => 'Invalid Credentials'
            ], Response::HTTP_UNAUTHORIZED);
        }

        $user = Auth::user();

        return response([
            'message' => 'Success',
            'token' => $user->createToken('token')->plainTextToken
        ]);

    }

    public function user(Request $request){
        return $user = Auth::user();
    }

    public function logout(Request $request){
        return Auth::user()->tokens()->delete();
    }
}
