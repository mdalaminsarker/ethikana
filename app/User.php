<?php

namespace App;

use Illuminate\Auth\Authenticatable;
use Laravel\Lumen\Auth\Authorizable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;
use App\Bike;
class User extends Model implements
    AuthenticatableContract,
    AuthorizableContract
{
    use Authenticatable, Authorizable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name',
        'email',
	      'password',
        'device_ID',
        'hasPendingRewardRequest',
        'user_last_lat',
        'user_last_lon'
    ];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
    public function reviews(){
        return $this->hasMany('App\ReviewRating');
    }
    public function places(){
        return $this->hasMany('App\Place');
    }
    public function moreInfo(){
        return $this->hasOne('App\AdditionalUserInfo','user_id');
    }
    public function vehicles(){
        return $this->hasMany('App\PoolVehicle','user_id');
    }
    public function proPic(){
        return $this->hasOne('App\ProfilePhoto','user_id');
    }
    public function poolPhoto(){
        return $this->hasMany('App\PoolPhoto','user_id');
    }
    public function bikes(){
        return $this->hasMany(Bike::class);
    }
}
