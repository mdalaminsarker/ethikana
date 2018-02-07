<?php namespace App;

use Illuminate\Database\Eloquent\Model;
use App\User;
class Bike extends Model {

    protected $table= 'Bike';
    protected $fillable = [
      'model_name','model_year','engine_capacity','engine_number','chassis_number',
      'registration_number',
      'bike_image_link',
      'paper_image_link',
      'hourly_rent',
      'daily_rent',
      'user_id',
      'last_serviced',
      'next_service',
      'availability'

    ];

    protected $dates = [];

    public static $rules = [
        // Validation rules
    ];

    // Relationships
    public function user()
   {
       return $this->belongsTo(User::class);
   }
}
