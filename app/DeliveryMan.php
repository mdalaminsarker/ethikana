<?php namespace App;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use \App\User;

class DeliveryMan extends Model {
    protected $table = 'DeliveryMan';
    protected $fillable = ['delivery_man_id','company_id','last_lon','last_lat','active','verified',];

    protected $dates = [];

    public static $rules = [
        // Validation rules
    ];

    public static function createDeliveryMan(Request $request, User $user)
    {

      $driver = DeliveryMan::create($request->all());
      $driver->delivery_man_id = $user->id;
      $driver->save();
    }

    // Relationships

}
