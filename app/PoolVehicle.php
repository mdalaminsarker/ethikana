<?php

namespace App;

use Illuminate\Database\Eloquent\Model;


class PoolVehicle extends Model
{
    //
    protected $table='pool_vehicles';
    protected $fillable=['isApproved',
    'isAllowedToServe'];
    // public function vehicle(){
    // 	return $this->belongsTo('App\OfferRide','vehcile_id');
    // }
    public function rideOwner(){
    	return $this->belongsTo('App\User','user_id');
    }
}
