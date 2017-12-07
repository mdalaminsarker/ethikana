<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreatePoolVehiclesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('pool_vehicles', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->unsigned();
            $table->string('vehicle_type')->nullable();// Bike-brand, Car-brand
            $table->string('vehicle_regnum')->nullable();//vehicle registration number
            $table->integer('vehicle_total_capacity')->nullable();//including the vehcile owner
            $table->tinyInteger('isApproved')->default(0);//vehicle+user profile approval,requires verification before Approval[0], after approval [1]
            $table->tinyInteger('isAllowedToServe')->default(0);//not allowed untill verified, can be set to 0 later if Service status needs to be changed 
            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('pool_vehicles');
    }
}
