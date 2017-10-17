<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class OfferRide extends Model
{
    //
	//protected $foreignkey='vehcile_id';
    public function user(){
    	return $this->belongsTo('App\User','user_id');
    }
    //change vehcile_id to vehicle_id in production
    public function vehicle(){
    	return $this->belongsTo('App\PoolVehicle','vehicle_id');
    }
    public function rideRequestBy(){
    	return $this->hasMany('App\BookARide','offer_rides_id');
    }
    // public function getThreadedComments(){
    //     return $this->comments()->with('user')->get()->threaded();
    // }
}
