from django.db import models

class Iot_Device(models.Model):
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=700, blank=True, null=True)
    IP_Address = models.GenericIPAddressField(protocol="both", unpack_ipv4=True, blank=True, null=True)
    Mac_Address = models.CharField(max_length=17, unique=True, blank=True, null=True)
    sector = models.ManyToManyField('Sector', related_name='Associated_Sector')
    def __str__(self):
        return self.name
    
class Sector(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.CharField(max_length=700, blank=True, null=True)

    def __str__(self):
        return self.name
    
class Threat(models.Model):
    threat_Level = models.CharField(max_length=50, choices=[
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical')
    ], blank=True, null=True)
    attack_Name = models.CharField(max_length=50, blank=True, null=True) # DOS
    description = models.CharField(max_length=700, blank=True, null=True) 
    devices = models.ManyToManyField('Iot_Device', related_name='threats')

    def __str__(self):
        return self.threat_Level + "-"  + self.attack_Name
    
class Threat_Detail(models.Model):
    Threat = models.ForeignKey('Threat', blank=True, null=True, on_delete=models.CASCADE, related_name='threat_details') 
    threat_Info_Category = models.ForeignKey('Threat_Info_Category', on_delete=models.CASCADE,blank=True, null=True) #known threats actors
    ai_summary = models.CharField(max_length=125,blank=True, null=True)
    details = models.TextField(blank=True, null=True) # China

        
    def __str__(self):
        return str(self.Threat) +": "+str(self.threat_Info_Category) #f"{self.threat.attack_Name} - {self.topic_of_details.topic}"

class Threat_Info_Category(models.Model):
    topic = models.CharField(max_length=50, unique=True,blank=True, null=True) #known threats actors
    description = models.CharField(max_length=700, blank=True, null=True)

    def __str__(self):
        return self.topic