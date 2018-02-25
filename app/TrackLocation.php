<?php namespace App;

use Illuminate\Database\Eloquent\Model;

class TrackLocation extends Model {

    protected $fillable = ['user_id','longitude','latitude'];

    protected $table = 'LocationTracker';

    public static $rules = [
        // Validation rules
    ];

    // Relationships

}
