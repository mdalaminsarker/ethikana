<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Place extends Model
{
    //
    protected $table='places';
    protected $fillable = [
        'longitude',
        'latitude',
        'Address',
        'flag',
        'device_ID',
        'uCode',
    ];
    public function business_details()
    {
        return $this->hasOne('App\BusinessDetails','business_pid');
    }
    public function reviews(){
        return $this->hasMany('App\ReviewRating','pid');
    }
    public function user(){
        return $this->belongsTo('App\User','user_id');
    }
    public function offer()
    {
        return $this->hasMany('App\Offer');
    }
    public function images()
    {
        return $this->hasMany('App\Image','pid');
    }
}
