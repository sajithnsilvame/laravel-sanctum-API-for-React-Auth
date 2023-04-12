<?php

namespace App\Http\Controllers\API;

use App\Models\User;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    // register
    public function register(Request $request){
        
        $validator = Validator::make($request->all(),[
           'name' => 'required|max:191',
           'email' => 'required|email|max:191|unique:users,email',
           'password' => 'required|min:8' 
        ]);

        if($validator->fails()){
            return response()->json([
                
                'validation_error' => $validator->messages()
            ]);
        }
        else{
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password)
            ]);

            $token = $user->createToken($user->email. '_Token')->plainTextToken;
            
            return response()->json([
                
                'status' => 200,
                'username' => $user->name,
                'token' => $token,
                'message' => 'Registered successfully!'
            ]);
        }
    }

    // login
    public function login(Request $request){
        
        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required' 
        ]);

        if($validator->fails()){
            return response()->json([
                'validation_error' => $validator->messages()
            ]);
        }
        else{
            
            $user = User::where('email', $request->email)->first();
 
            if (!$user || !Hash::check($request->password, $user->password)) {
                return response()->json([
                   'status' => 401,
                   'message' => 'Invalid Credentials' 
                ]);
            }
            else{
                
                $token = $user->createToken($user->email. '_Token')->plainTextToken;
                return response()->json([
                    'status' => 200,
                    'username' => $user->name,
                    'token' => $token,
                    'message' => 'Logged in successfully!'
                ]);
            }
        }
    }

    // logout
    public function logout(Request $request){
        
        // auth()->user()->token()->delete();
        $request->user()->currentAccessToken()->delete(); 
        return response()->json([
            'status' => 200,
            'message' => 'Logout Succssfully!'
        ]);
    }
}