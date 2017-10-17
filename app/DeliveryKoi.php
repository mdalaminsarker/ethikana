<?php namespace App;

use Illuminate\Database\Eloquent\Model;

class DeliveryKoi extends Model {

    protected $fillable = [
      "sender_name", "sender_number","pick_up","drop_off","date","receivers_name",
    "receivers_number", "user_id","preffered_time","delivery_status",
    "delivery_man_name","delivery_man_number","delivery_company"];

    //protected $dates = ["due"];

  /*  public static $rules = [
        "sender_name" => "required",
        "project_id" => "numeric",
        "user_id" => "required|numeric",
    ];
*/
    public function user()
    {
        return $this->belongsTo("App\User");
    }


}
