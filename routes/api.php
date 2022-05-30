<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;


/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
Route::post('auth/login', [AuthController::class, 'login']);
Route::post('auth/register', [AuthController::class, 'register']);
Route::group([
    'middleware' => 'jwt.verify',
    'prefix' => 'auth'

], function ($router) {

    Route::get('/logout', [AuthController::class, 'logout']);
    Route::post('/refresh', [AuthController::class, 'refresh']);
    Route::get('/user-profile', [AuthController::class, 'userProfile']);
});


Route::group( ['middleware' => 'jwt.verify'], function()
{
    Route::get('/users', [AuthController::class, 'userList']);

});
Route::post('/forgot-password', [AuthController::class, 'submitForgetPasswordForm']);
Route::post('/reset-password', [AuthController::class, 'submitResetPasswordForm']);

