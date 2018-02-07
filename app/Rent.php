<?php namespace App;

use Illuminate\Database\Eloquent\Model;

class Rent extends Model {
    protected $table = 'Rent';
    protected $fillable = ['user_id','bike_id','requested_time','start_time','end_time','total_rent',
    'rent_type','rent_status',

    ];

    protected $dates = [];

    public static $rules = [
        // Validation rules
    ];

    // Relationships



}
