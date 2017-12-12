<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateDeliveryKoisTable extends Migration
{

    public function up()
    {
        Schema::create('DeliveryKois', function(Blueprint $table) {
            $table->increments('id');
            $table->string('sender_name')->nullable();
            $table->string('sender_number')->nullable();
            $table->string('pick_up')->nullable();
            $table->string('pick_up_lon')->nullable();
            $table->string('pick_up_lat')->nullable();
            $table->string('drop_off')->nullable();
            $table->string('drop_off_lon')->nullable();
            $table->string('drop_off_lat')->nullable();
            $table->date('pick_up_date')->nullable();
            $table->time('preffered_time')->nullable();
            $table->string('product')->nullable();
            $table->integer('product_weight')->nullable();
            $table->integer('product_price')->nullable();
            $table->string('receivers_name')->nullable();
            $table->string('receivers_number')->nullable();
            $table->string('delivery_man_name')->nullable();
            $table->string('delivery_man_number')->nullable();
            $table->string('delivery_company')->nullable();
            $table->string('delivery_fee')->nullable();
            $table->integer('delivery_status')->default(0);
            $table->integer('delivery_mans_id')->nullable();
            $table->integer('user_id')->unsigned();
            $table->string('verification_code')->nullable();
            $table->foreign('user_id')->references('id')->on('users');
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::drop('DeliveryKois');
    }
}
