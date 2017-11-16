<?php namespace App;

use Illuminate\Database\Eloquent\Model;

class RideTechsRequestRides extends Model {

    protected $table = 'ridetechs_request_rides';
    protected $fillable = [

      'start_point',
      'destination',
      'pickup_time_from_home',
      'pickup_time_from_office',
      'day_in_week',
      'contact_number',
      'name',
      'user_id'
    ];

    protected $dates = [];

    public static $rules = [
        // Validation rules
    ];

    // Relationships

}
