<?php namespace App;

use Illuminate\Database\Eloquent\Model;

class RideTechsOfferRides extends Model {

    protected $table = 'ridetechs_offer_rides';
    protected $fillable = [
      'start_point',
      'destination',
      'pickup_time',
      'dropoff_time',
      'day_in_week',
      'car_model',
      'name',
      'number',
      'user_id',
    ];

    protected $dates = [];

    public static $rules = [
        // Validation rules
    ];

    // Relationships

}
