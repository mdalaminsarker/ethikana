<?php namespace App;

use Illuminate\Database\Eloquent\Model;

class DeliveryKoi extends Model {

    protected $fillable = [
    "sender_name", "sender_number","pick_up","pick_up_lon","pick_up_lat","drop_off","drop_off_lon","drop_off_lat","pick_up_date","receivers_name",
    "receivers_number", "user_id","preffered_time","product","product_weight","product_price","delivery_status",
    "delivery_mans_id","delivery_man_name","delivery_man_number","delivery_company","delivery_fee","verification_code"];

    protected $table = 'DeliveryKois';
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
