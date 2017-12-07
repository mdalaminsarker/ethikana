<?php namespace App;

use Illuminate\Database\Eloquent\Model;

class RideTechs extends Model {


    protected $table = 'ridetechs';
    protected $fillable = [
        'start_point',
        'destination',
        'pickup_time',
        'dropoff_time',
        'day_in_week',
        'estimated_fare',
        'car_model',

    ];

    protected $dates = [];

    public static $rules = [
        // Validation rules
    ];

    // Relationships

}
