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
        return $this->hasOne('BusinessDetails','business_pid');
    }
    
    public function reviews(){
        return $this->hasMany('App\ReviewRating','pid');
    }
    public function user()
    {
        return $this->belongsTo('App\User');
    }
        public function offer()
    {
        return $this->hasMany('App\Offer');
    }
}
